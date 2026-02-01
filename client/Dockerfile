FROM python:3.10-slim
RUN pip install requests cryptography
WORKDIR /app
COPY client.py .
CMD ["python", "client.py"]
