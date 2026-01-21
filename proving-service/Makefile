.PHONY: build build-cpu up up-cpu logs logs-cpu down down-cpu

build: ## Build the proving service and benchmark Docker images with CUDA
	docker compose build

build-cpu: ## Build the proving service with CPU-only (no CUDA)
	docker compose -f docker-compose.cpu.yml build

up: ## Start the proving service in background
	docker compose up -d

up-cpu: ## Start the CPU-only proving service in background
	docker compose -f docker-compose.cpu.yml up -d

logs: ## Show logs from proving service
	docker compose logs -f proving-service

logs-cpu: ## Show logs from CPU proving service
	docker compose -f docker-compose.cpu.yml logs -f proving-service

down: ## Stop all services
	docker compose down

down-cpu: ## Stop CPU services
	docker compose -f docker-compose.cpu.yml down
