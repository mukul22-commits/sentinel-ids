.DEFAULT_GOAL := help

COMPOSE := docker compose --env-file .env -f infra/docker-compose.yml

.PHONY: help up down logs backend-shell lint test format build

help: ## List available make targets
	@echo "Sentinel IDS Platform - developer commands"
	@echo ""
	@echo "  make up             Start all services (postgres, redis, backend, frontend)"
	@echo "  make down           Stop all services"
	@echo "  make logs           Tail logs for all services"
	@echo "  make backend-shell  Open a shell inside the backend container"
	@echo "  make lint           Run Python + frontend linters and type checks"
	@echo "  make test           Run backend tests (pytest)"
	@echo "  make format         Auto-format Python + frontend code"
	@echo "  make build          Build backend + frontend Docker images"

up: ## Start all services
	$(COMPOSE) up -d --build

down: ## Stop all services
	$(COMPOSE) down

logs: ## Tail logs for all services
	$(COMPOSE) logs -f --tail=100

backend-shell: ## Open a shell in the backend container
	$(COMPOSE) exec backend sh

lint: ## Run all linters and type checks
	cd backend && ruff check . && black --check . && mypy app
	cd frontend && npm run lint && npm run format:check && npm run typecheck

test: ## Run backend tests
	cd backend && pytest

format: ## Auto-format Python + frontend code
	cd backend && black . && ruff check . --fix
	cd frontend && npm run format

build: ## Build Docker images
	$(COMPOSE) build
