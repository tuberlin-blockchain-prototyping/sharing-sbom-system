# Dummy Application

A simple Python Flask application used for SBOM generation testing in the CI/CD pipeline.

## Dependencies

- Flask - Web framework
- requests - HTTP library
- PyYAML - YAML parser
- python-dateutil - Date utilities
- cryptography - Cryptographic library

## Usage

The application provides two endpoints:
- `GET /` - Returns application info
- `GET /health` - Health check endpoint

## Docker

Build the image:
```bash
docker build -t dummyapp:latest -f dummyapp/Dockerfile dummyapp/
```

Run the container:
```bash
docker run -p 8080:8080 dummyapp:latest
```

