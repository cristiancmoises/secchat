FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    fastapi==0.111.0 \
    "uvicorn[standard]==0.29.0" \
    jinja2==3.1.4 \
    python-multipart==0.0.9 \
    cryptography==42.0.8 \
    argon2-cffi==23.1.0

COPY main.py .
COPY *.html ./templates/

ENV SERVER_SECRET="change-this-to-a-random-64-char-string-before-deploying!!"
ENV PYTHONUNBUFFERED=1

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
