# Dummyapp2

Node.js "Hello World" application with for testing SBOM generation.

## Dependencies

- None! Uses only Node.js built-in `http` module

## Build

```bash
docker build -t dummyapp2:latest -f dummyapp2/Dockerfile .
```

## Run

```bash
docker run -p 8080:8080 dummyapp2:latest
```
