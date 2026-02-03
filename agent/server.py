import os
import json
import binascii
import asyncio

from flask import Flask, request, jsonify

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agent_core import run_agent_step
from flask_cors import CORS


# -------------------------------------------------
# App
# -------------------------------------------------
app = Flask(__name__)
CORS(app)


# -------------------------------------------------
# Utils
# -------------------------------------------------
def hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()


def unhex(s: str) -> bytes:
    return binascii.unhexlify(s)


# -------------------------------------------------
# GLOBAL AGENT KEY (UI ↔ Agent encryption)
# -------------------------------------------------
agent_key = ec.generate_private_key(ec.SECP256R1())


# -------------------------------------------------
# CRYPTO: UI → Agent
# -------------------------------------------------
def decrypt_from_ui(data: dict):
    client_pub = unhex(data["client_pub"])
    iv = unhex(data["nonce"])
    ct = unhex(data["ciphertext"])

    client_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), client_pub
    )

    shared = agent_key.exchange(ec.ECDH(), client_key)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-chat",
    ).derive(shared)

    aes = AESGCM(aes_key)
    plaintext = aes.decrypt(iv, ct, None).decode()

    return json.loads(plaintext), aes


def encrypt_to_ui(aes: AESGCM, obj: dict):
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, json.dumps(obj).encode(), None)
    return {
        "nonce": hex(nonce),
        "ciphertext": hex(ct),
    }


# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.route("/agent/pubkey", methods=["GET"])
def agent_pubkey():
    pub = agent_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return hex(pub)


@app.route("/agent/chat", methods=["POST"])
def agent_chat():
    """
    Encrypted Agent endpoint.
    Flask (sync) → asyncio MCP agent → encrypted response
    """
    payload, aes = decrypt_from_ui(request.json)

    user_prompt = payload["prompt"]
    context = payload.get("context", {})

    # ---- IMPORTANT FIX ----
    # MCP is async → bridge with asyncio.run
    result = asyncio.run(
        run_agent_step(
            user_prompt=user_prompt,
            context=context,
        )
    )

    return jsonify(encrypt_to_ui(aes, result))


# -------------------------------------------------
# ENTRYPOINT
# -------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000, debug=True)
