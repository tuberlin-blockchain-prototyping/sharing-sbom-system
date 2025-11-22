.PHONY: help build run docker-build docker-run test clean

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

build: ## Build the Go binary
	go build -o merkle-proof-service .

run: ## Run the service locally
	go run .

docker-build: ## Build Docker image
	docker build -t merkle-proof-service:latest .

docker-run: ## Run the service in Docker
	docker run -p 8090:8090 merkle-proof-service:latest

test: ## Run the test script
	cd examples && ./test-service.sh

clean: ## Clean build artifacts
	rm -f merkle-proof-service
	go clean

