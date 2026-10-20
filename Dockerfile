FROM python:3.13-slim

WORKDIR /opt/sigint-console

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIGINT_HOST=0.0.0.0 \
    SIGINT_PORT=47891 \
    SIGINT_HTTPS_PORT=47892 \
    SIGINT_DATA_DIR=/data

RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
COPY app/ /opt/sigint-console/app/
RUN mkdir -p /data/jsonl /data/pcap

EXPOSE 47891 47892

CMD ["python3", "/opt/sigint-console/app/server.py", "--host", "0.0.0.0", "--port", "47891", "--https-port", "47892", "--data", "/data"]
