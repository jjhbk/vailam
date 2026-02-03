from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from llama_cpp import Llama
import os, binascii, gc, json
from flask import Response, stream_with_context


app = Flask(__name__)
CORS(app)


# --------------------
# Utils
# --------------------
def hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()


def unhex(s: str) -> bytes:
    return binascii.unhexlify(s)


# --------------------
# GLOBAL CRYPTO STATE
# --------------------
server_key = ec.generate_private_key(ec.SECP256R1())

# --------------------
# GLOBAL LLM
# --------------------
MODEL_PATH = os.getenv("MODEL_PATH", "../data/mistral.gguf")

if not os.path.exists(MODEL_PATH):
    print("Downloading model...")
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    os.system(
        "wget https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/"
        "resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf "
        f"-O {MODEL_PATH}"
    )

llm = Llama(model_path=MODEL_PATH, n_ctx=2048, n_threads=16)


SYSTEM_PROMPT = "You are a helpful, concise assistant."

SUMMARY_SYSTEM_PROMPT = (
    "You are updating a long-term memory for an AI assistant.\n\n"
    "Extract ONLY the important information that should be remembered "
    "for future conversations.\n\n"
    "Rules:\n"
    "- Do NOT include dialogue or greetings\n"
    "- Do NOT include assistant phrasing\n"
    "- Keep it factual and concise\n"
    "- Include user goals, preferences, constraints, and decisions\n"
    "- Max 120 tokens\n\n"
    "Return ONLY the updated memory."
)

MCP_SYSTEM_PROMPT = (
    "You are an MCP agent.\n"
    "You MUST respond with valid JSON only.\n\n"
    "If a tool is required, respond with:\n"
    "{\n"
    '  "tool": "<tool_name>",\n'
    '  "arguments": { ... }\n'
    "}\n\n"
    "If no tool is needed, respond with:\n"
    '{ "final": "<your response>" }\n\n'
    "Do NOT include markdown, comments, or extra text."
)


# --------------------
# ROUTES
# --------------------
@app.route("/pubkey", methods=["GET"])
def pubkey():
    pub = server_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return hex(pub)


def decrypt_payload(data):
    client_pub = unhex(data["client_pub"])
    iv = unhex(data["nonce"])
    ct = unhex(data["ciphertext"])

    client_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), client_pub
    )

    shared = server_key.exchange(ec.ECDH(), client_key)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-chat",
    ).derive(shared)

    aes = AESGCM(aes_key)
    plaintext = aes.decrypt(iv, ct, None).decode()

    return json.loads(plaintext), aes


@app.route("/chat", methods=["POST"])
def chat():
    payload, aes = decrypt_payload(request.json)

    prompt = payload["prompt"].strip()
    params = payload.get("params", {})
    mode = params.get("mode", "chat")
    context = payload.get("context", {})

    summary = context.get("summary", "")
    recent = context.get("recent", [])

    temperature = float(params.get("temperature", 0.7))
    max_tokens = int(params.get("max_tokens", 128))

    temperature = max(0.0, min(temperature, 1.5))
    max_tokens = max(16, min(max_tokens, 512))

    messages = [
        {
            "role": "system",
            "content": MCP_SYSTEM_PROMPT if mode == "tool" else SYSTEM_PROMPT,
        }
    ]

    if summary:
        messages.append(
            {"role": "system", "content": f"Conversation summary:\n{summary}"}
        )

    for m in recent:
        if m["role"] in ("user", "assistant"):
            messages.append(m)

    messages.append({"role": "user", "content": prompt})

    result = llm.create_chat_completion(
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )

    raw_out = result["choices"][0]["message"]["content"].strip()

    if mode == "tool":
        try:
            llm_out = json.dumps(json.loads(raw_out))
        except Exception:
            llm_out = json.dumps({"final": raw_out})
    else:
        llm_out = raw_out

    out_nonce = os.urandom(12)
    out_ct = aes.encrypt(out_nonce, llm_out.encode(), None)

    del messages, result
    gc.collect()

    return jsonify(
        {
            "ciphertext": hex(out_ct),
            "nonce": hex(out_nonce),
        }
    )


@app.route("/summarize", methods=["POST"])
def summarize():
    payload, aes = decrypt_payload(request.json)

    previous_summary = payload.get("summary", "")
    recent = payload.get("recent", [])

    convo_text = ""
    for m in recent:
        role = m["role"].upper()
        convo_text += f"{role}: {m['content']}\n"

    messages = [
        {"role": "system", "content": SUMMARY_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Current memory:\n{previous_summary}\n\n"
                f"Recent conversation:\n{convo_text}"
            ),
        },
    ]

    result = llm.create_chat_completion(
        messages=messages,
        temperature=0.2,
        max_tokens=120,
    )

    new_summary = result["choices"][0]["message"]["content"].strip()

    out_nonce = os.urandom(12)
    out_ct = aes.encrypt(out_nonce, new_summary.encode(), None)

    del messages, result
    gc.collect()

    return jsonify(
        {
            "ciphertext": hex(out_ct),
            "nonce": hex(out_nonce),
        }
    )


@app.route("/chat/stream", methods=["POST"])
def chat_stream():
    payload, aes = decrypt_payload(request.json)

    prompt = payload["prompt"].strip()
    params = payload.get("params", {})
    mode = params.get("mode", "chat")
    context = payload.get("context", {})

    # 🚫 MCP/tool mode must NOT use streaming
    if mode == "tool":
        return jsonify({"error": "Streaming is not supported in MCP tool mode"}), 400

    temperature = float(params.get("temperature", 0.7))
    max_tokens = int(params.get("max_tokens", 128))

    temperature = max(0.0, min(temperature, 1.5))
    max_tokens = max(16, min(max_tokens, 512))

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    if context.get("summary"):
        messages.append(
            {
                "role": "system",
                "content": f"Conversation summary:\n{context['summary']}",
            }
        )

    for m in context.get("recent", []):
        if m["role"] in ("user", "assistant"):
            messages.append(m)

    messages.append({"role": "user", "content": prompt})

    def generate():
        for chunk in llm.create_chat_completion(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
        ):
            delta = chunk["choices"][0].get("delta", {})
            token = delta.get("content")

            if not token:
                continue

            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, token.encode(), None)

            yield json.dumps(
                {
                    "ciphertext": hex(ct),
                    "nonce": hex(nonce),
                }
            ) + "\n"

    return Response(
        stream_with_context(generate()),
        mimetype="application/json",
    )


@app.route("/capabilities", methods=["GET"])
def capabilities():
    return jsonify(
        {
            "mcp": True,
            "json_mode": True,
            "streaming": True,
            "encryption": "ECDH+AESGCM",
            "max_context": 2048,
            "model": "llama.cpp",
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
