FROM python:3.11-slim

WORKDIR /app

RUN mkdir -p /data

COPY ipfs-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ipfs-service/ .

EXPOSE 8080

ENV PORT=8080
ENV IPFS_HOST=localhost
ENV IPFS_PORT=5001
ENV IPFS_PROTOCOL=http
ENV DB_PATH=/data/ipfs.db

CMD ["python", "app.py"]

