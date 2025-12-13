FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

COPY merkle-proof-service/go.mod ./
RUN go mod download

COPY merkle-proof-service/ .

RUN go mod tidy

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -installsuffix cgo -o merkle-proof-service .

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /build/merkle-proof-service .

RUN mkdir -p /app/data

EXPOSE 8090

CMD ["./merkle-proof-service"]
