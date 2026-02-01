import requests, os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization


def derive_key(shared):
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"veilai-session"
    ).derive(shared)


# Fetch enclave public key
server_pub = requests.get("http://secure-llm:5000/pubkey").content
server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)

# Client ephemeral key
client_private = x25519.X25519PrivateKey.generate()
client_public = client_private.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
)

shared = client_private.exchange(server_public)
key = derive_key(shared)
aes = AESGCM(key)

nonce = os.urandom(12)
prompt = "Explain zero trust in simple words"
ct = aes.encrypt(nonce, prompt.encode(), None)

resp = requests.post(
    "http://secure-llm:5000/chat",
    json={
        "client_pub": client_public.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
    },
)

pt = aes.decrypt(nonce, bytes.fromhex(resp.json()["ciphertext"]), None)
print("LLM:", pt.decode())
