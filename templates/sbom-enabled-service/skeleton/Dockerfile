{% if values.language == 'python' %}
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["python", "app.py"]
{% elif values.language == 'nodejs' %}
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 8080

CMD ["node", "app.js"]
{% elif values.language == 'rust' %}
FROM rust:1.70 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/${{ values.name }} /usr/local/bin/app

EXPOSE 8080

CMD ["app"]
{% endif %}
