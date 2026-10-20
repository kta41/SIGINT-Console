FROM python:3.13-slim

WORKDIR /opt/sigint-console

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIGINT_HOST=0.0.0.0 \
    SIGINT_PORT=8080 \
    SIGINT_DATA_DIR=/data

COPY app/ /opt/sigint-console/app/
RUN mkdir -p /data

EXPOSE 8080

CMD ["python3", "/opt/sigint-console/app/server.py", "--host", "0.0.0.0", "--port", "8080", "--data", "/data"]
