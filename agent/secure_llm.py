import os
import json
import binascii
import requests

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# -------------------------------------------------
# CONFIG
# -------------------------------------------------
ENCLAVE_URL = "http://localhost:5000"
CHAT_ENDPOINT = f"{ENCLAVE_URL}/chat"


# -------------------------------------------------
# UTILS
# -------------------------------------------------
def hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()


def unhex(s: str) -> bytes:
    return binascii.unhexlify(s)


# -------------------------------------------------
# SECURE LLM CALL
# -------------------------------------------------
def secure_llm_call(prompt: str, context=None) -> str:
    """
    Makes an encrypted call to the secure enclave /chat endpoint.
    Returns DECRYPTED plaintext (string).
    """

    # 1️⃣ Fetch enclave public key
    spk_hex = requests.get(f"{ENCLAVE_URL}/pubkey").text
    server_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), unhex(spk_hex)
    )

    # 2️⃣ Generate client keypair
    client_key = ec.generate_private_key(ec.SECP256R1())
    client_pub = client_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    # 3️⃣ Derive shared secret
    shared = client_key.exchange(ec.ECDH(), server_pub)

    # 4️⃣ Derive AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-chat",
    ).derive(shared)

    aes = AESGCM(aes_key)

    # 5️⃣ Encrypt payload
    payload = {
        "prompt": prompt,
        "context": context or {},
        "params": {
            "mode": "tool",
            "temperature": 0.2,
            "max_tokens": 256,
        },
    }

    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, json.dumps(payload).encode(), None)

    # 6️⃣ Send encrypted request
    resp = requests.post(
        CHAT_ENDPOINT,
        json={
            "client_pub": hex(client_pub),
            "nonce": hex(nonce),
            "ciphertext": hex(ct),
        },
        timeout=120,
    )
    resp.raise_for_status()

    # 7️⃣ Decrypt response
    data = resp.json()
    pt = aes.decrypt(
        unhex(data["nonce"]),
        unhex(data["ciphertext"]),
        None,
    )

    return pt.decode()
