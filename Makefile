.PHONY: help build test test-unit test-integration test-watch test-coverage test-coverage-unit test-coverage-integration test-benchmark test-clean test-db-setup test-db-cleanup test-db-reset clean dev deps generate migrate lint format security audit docker health

# Colors for output
RED    := \033[31m
GREEN  := \033[32m
YELLOW := \033[33m
BLUE   := \033[34m
RESET  := \033[0m

# Project variables
PROJECT_NAME := askfrank
BINARY_NAME := askfrank
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go variables
GO_VERSION := 1.21
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOLINT := golangci-lint

# Database variables
DB_HOST := localhost
DB_PORT := 5432
DB_USER := postgres
DB_PASSWORD := postgres
DB_NAME := postgres
DB_URL := postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable

# Build flags
LDFLAGS := -X 'main.version=$(VERSION)' -X 'main.buildTime=$(BUILD_TIME)' -X 'main.commitHash=$(COMMIT_HASH)'
BUILD_FLAGS := -ldflags "$(LDFLAGS)"

## help: Show this help message
help:
	@echo "$(BLUE)AskFrank Healthcare IT Platform$(RESET)"
	@echo "$(BLUE)================================$(RESET)"
	@echo ""
	@echo "$(GREEN)Available commands:$(RESET)"
	@grep -E '^## .*:.*' $(MAKEFILE_LIST) | sed 's/## \(.*\): \(.*\)/  $(GREEN)\1$(RESET) - \2/'

## deps: Install dependencies
deps:
	@echo "$(BLUE)Installing dependencies...$(RESET)"
	$(GOMOD) download
	$(GOMOD) verify
	@if ! command -v templ >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing templ...$(RESET)"; \
		$(GOCMD) install github.com/a-h/templ/cmd/templ@latest; \
	fi
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing golangci-lint...$(RESET)"; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin; \
	fi
	@if ! command -v migrate >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing migrate...$(RESET)"; \
		$(GOCMD) install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest; \
	fi

## generate: Generate templ templates and other code
generate:
	@echo "$(BLUE)Generating templates...$(RESET)"
	templ generate
	@echo "$(GREEN)Templates generated successfully$(RESET)"

## format: Format Go code
format:
	@echo "$(BLUE)Formatting code...$(RESET)"
	$(GOFMT) -w .
	$(GOCMD) mod tidy
	@echo "$(GREEN)Code formatted successfully$(RESET)"

## lint: Run linters
lint:
	@echo "$(BLUE)Running linters...$(RESET)"
	$(GOLINT) run --timeout=5m
	@echo "$(GREEN)Linting completed$(RESET)"

## test: Run all tests
test:
	@echo "$(BLUE)Running all tests...$(RESET)"
	$(GOCMD) run tests/test_runner.go
	@echo "$(GREEN)All tests completed$(RESET)"

## test-unit: Run unit tests only
test-unit:
	@echo "$(BLUE)Running unit tests...$(RESET)"
	$(GOTEST) -v -race -coverprofile=coverage-unit.out ./tests/service/... ./tests/validator/...
	@echo "$(GREEN)Unit tests completed$(RESET)"

## test-integration: Run integration tests only
test-integration: test-db-setup
	@echo "$(BLUE)Running integration tests...$(RESET)"
	$(GOTEST) -v -race -coverprofile=coverage-integration.out ./tests/integration/...
	@echo "$(GREEN)Integration tests completed$(RESET)"

## test-watch: Run tests in watch mode
test-watch:
	@echo "$(BLUE)Running tests in watch mode...$(RESET)"
	$(GOCMD) run github.com/githubnemo/CompileDaemon@latest -command="make test-unit"

## test-coverage: Run tests with coverage report
test-coverage: test
	@echo "$(BLUE)Generating coverage report...$(RESET)"
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(RESET)"

## test-coverage-unit: Generate unit test coverage report
test-coverage-unit: test-unit
	@echo "$(BLUE)Generating unit test coverage report...$(RESET)"
	$(GOCMD) tool cover -html=coverage-unit.out -o coverage-unit.html
	@echo "$(GREEN)Unit test coverage report generated: coverage-unit.html$(RESET)"

## test-coverage-integration: Generate integration test coverage report
test-coverage-integration: test-integration
	@echo "$(BLUE)Generating integration test coverage report...$(RESET)"
	$(GOCMD) tool cover -html=coverage-integration.out -o coverage-integration.html
	@echo "$(GREEN)Integration test coverage report generated: coverage-integration.html$(RESET)"

## test-benchmark: Run benchmark tests
test-benchmark:
	@echo "$(BLUE)Running benchmark tests...$(RESET)"
	$(GOTEST) -bench=. -benchmem ./tests/...
	@echo "$(GREEN)Benchmark tests completed$(RESET)"

## test-clean: Clean test artifacts
test-clean:
	@echo "$(BLUE)Cleaning test artifacts...$(RESET)"
	rm -f coverage*.out coverage*.html
	@echo "$(GREEN)Test artifacts cleaned$(RESET)"

## test-db-setup: Setup test database
test-db-setup:
	@echo "$(BLUE)Setting up test database...$(RESET)"
	@echo "$(BLUE)Starting PostgreSQL if not running...$(RESET)"
	-docker compose up -d postgres 2>/dev/null || true
	@sleep 2
	@echo "$(BLUE)Creating test database...$(RESET)"
	-docker compose exec -T postgres createdb -U postgres askfrank_test 2>/dev/null || true
	@echo "$(GREEN)Test database setup completed$(RESET)"

## test-db-cleanup: Cleanup test database
test-db-cleanup:
	@echo "$(BLUE)Cleaning up test database...$(RESET)"
	-docker compose exec -T postgres dropdb -U postgres askfrank_test 2>/dev/null || true
	@echo "$(GREEN)Test database cleanup completed$(RESET)"

## test-db-reset: Reset test database
test-db-reset: test-db-cleanup test-db-setup
	@echo "$(GREEN)Test database reset completed$(RESET)"

## build: Build the application
build: generate
	@echo "$(BLUE)Building $(PROJECT_NAME)...$(RESET)"
	$(GOBUILD) $(BUILD_FLAGS) -o bin/$(BINARY_NAME) .
	@echo "$(GREEN)Build completed: bin/$(BINARY_NAME)$(RESET)"

## build-prod: Build for production
build-prod: generate format lint test
	@echo "$(BLUE)Building production binary...$(RESET)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -a -installsuffix cgo -o bin/$(BINARY_NAME)-linux-amd64 .
	@echo "$(GREEN)Production build completed$(RESET)"

## dev: Run development server with hot reload
dev: generate
	@echo "$(BLUE)Starting development server...$(RESET)"
	@if command -v air >/dev/null 2>&1; then \
		hair; \
	else \
		echo "$(YELLOW)Air not found, installing...$(RESET)"; \
		$(GOCMD) install github.com/cosmtrek/air@latest; \
		air; \
	fi

## run: Run the application
run: build
	@echo "$(BLUE)Starting $(PROJECT_NAME)...$(RESET)"
	./bin/$(BINARY_NAME)

## migrate-up: Run database migrations
migrate-up:
	@echo "$(BLUE)Running database migrations...$(RESET)"
	migrate -path migrations -database "$(DB_URL)" up
	@echo "$(GREEN)Migrations completed$(RESET)"

## migrate-down: Rollback database migrations
migrate-down:
	@echo "$(BLUE)Rolling back database migrations...$(RESET)"
	migrate -path migrations -database "$(DB_URL)" down
	@echo "$(GREEN)Rollback completed$(RESET)"

## migrate-create: Create a new migration file
migrate-create:
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir migrations $$name
	@echo "$(GREEN)Migration files created$(RESET)"

## security: Run security checks
security:
	@echo "$(BLUE)Running security checks...$(RESET)"
	@if ! command -v gosec >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing gosec...$(RESET)"; \
		$(GOCMD) install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
	fi
	gosec ./...
	@echo "$(GREEN)Security checks completed$(RESET)"

## audit: Run dependency audit
audit:
	@echo "$(BLUE)Running dependency audit...$(RESET)"
	@if ! command -v nancy >/dev/null 2>&1; then \
		echo "$(YELLOW)Nancy not found. Please install it manually: https://github.com/sonatype-nexus-community/nancy$(RESET)"; \
		exit 1; \
	fi
	$(GOCMD) list -json -deps ./... | nancy sleuth
	@echo "$(GREEN)Dependency audit completed$(RESET)"

## docker-build: Build Docker image
docker-build:
	@echo "$(BLUE)Building Docker image...$(RESET)"
	docker build -t $(PROJECT_NAME):$(VERSION) .
	docker tag $(PROJECT_NAME):$(VERSION) $(PROJECT_NAME):latest
	@echo "$(GREEN)Docker image built: $(PROJECT_NAME):$(VERSION)$(RESET)"

## docker-run: Run Docker container
docker-run:
	@echo "$(BLUE)Running Docker container...$(RESET)"
	docker run -p 8080:8080 --name $(PROJECT_NAME) $(PROJECT_NAME):latest

## docker-stop: Stop Docker container
docker-stop:
	@echo "$(BLUE)Stopping Docker container...$(RESET)"
	docker stop $(PROJECT_NAME) || true
	docker rm $(PROJECT_NAME) || true

## health: Check application health
health:
	@echo "$(BLUE)Checking application health...$(RESET)"
	@curl -f http://localhost:8080/health >/dev/null 2>&1 && \
		echo "$(GREEN)Application is healthy$(RESET)" || \
		echo "$(RED)Application is not responding$(RESET)"

## clean: Clean build artifacts
clean:
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -f *.log
	$(GOCMD) clean -cache
	@echo "$(GREEN)Clean completed$(RESET)"

## setup: Initial project setup
setup: deps generate migrate-up
	@echo "$(GREEN)Project setup completed$(RESET)"

## ci: Continuous integration pipeline
ci: deps generate format lint test security build
	@echo "$(BLUE)Verifying security configuration...$(RESET)"
	@if [ -z "$$CSRF_SECRET" ]; then echo "$(YELLOW)Warning: CSRF_SECRET not set$(RESET)"; fi
	@if [ -z "$$JWT_SECRET" ]; then echo "$(YELLOW)Warning: JWT_SECRET not set$(RESET)"; fi
	@echo "$(GREEN)CI pipeline completed$(RESET)"

## info: Show project information
info:
	@echo "$(BLUE)Project Information$(RESET)"
	@echo "$(BLUE)==================$(RESET)"
	@echo "Name: $(PROJECT_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Commit: $(COMMIT_HASH)"
	@echo "Go Version: $(shell $(GOCMD) version)"
