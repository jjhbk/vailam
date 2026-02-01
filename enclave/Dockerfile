# =========================
# 1️⃣ BUILDER STAGE
# =========================
FROM python:3.10-slim AS builder

RUN apt update && apt install -y \
    build-essential \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Install pip deps into a temp location
RUN pip install --upgrade pip

RUN pip install \
    flask \
    flask-cors \
    cryptography \
    llama-cpp-python \
    --no-cache-dir \
    --prefix=/install


# =========================
# 2️⃣ RUNTIME STAGE
# =========================
FROM python:3.10-slim

# Only runtime libs (NO compilers)
RUN apt update && apt install -y \
    libstdc++6 \
    libgomp1 \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy only installed Python packages
COPY --from=builder /install /usr/local

WORKDIR /app
COPY secure_worker.py .

# Directory for model cache (mounted or downloaded)
RUN mkdir -p /data

ENV MODEL_PATH=/data/tiny.gguf

# 🔥 Model is NOT in the image
# secure_worker.py should download if missing

CMD ["python", "secure_worker.py"]
