.PHONY: help build test clean dev deps generate migrate lint format security audit docker health
.PHONY: migrate-up migrate-down migrate-down-all migrate-reset migrate-status migrate-goto migrate-force migrate-create migrate-validate migrate-list
.PHONY: migrate-tool-up migrate-tool-down migrate-tool-status migrate-tool-create migrate-script-help migrate-script
.PHONY: test-unit test-integration test-coverage test-coverage-unit test-coverage-integration test-coverage-html test-watch test-benchmark test-clean test-db-setup test-db-cleanup test-db-reset
.PHONY: docker-compose-up docker-compose-down docker-compose-restart docker-compose-logs docker-compose-logs-postgres docker-compose-logs-alloy docker-compose-status docker-build docker-run docker-stop
.PHONY: security-fix security-report audit

# Load environment variables from .env file if it exists
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

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
GOLINT := ~/go/bin/golangci-lint
GOAIR :=  ~/go/bin/air --build.cmd "go build -o bin/askfrank cmd/main.go" --build.bin "./bin/askfrank"

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
	@echo "$(BLUE)╔════════════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║                    AskFrank Healthcare IT Platform                     ║$(RESET)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(GREEN)📋 Available Commands:$(RESET)"
	@echo ""
	@echo "$(YELLOW)🏗️  Development & Build:$(RESET)"
	@echo "  $(GREEN)deps$(RESET)               - Install dependencies"
	@echo "  $(GREEN)generate$(RESET)           - Generate templ templates and other code"
	@echo "  $(GREEN)format$(RESET)             - Format Go code"
	@echo "  $(GREEN)lint$(RESET)               - Run linters"
	@echo "  $(GREEN)build$(RESET)              - Build the application"
	@echo "  $(GREEN)build-prod$(RESET)         - Build for production"
	@echo "  $(GREEN)dev$(RESET)                - Run development server with hot reload"
	@echo "  $(GREEN)run$(RESET)                - Run the application"
	@echo "  $(GREEN)clean$(RESET)              - Clean build artifacts"
	@echo ""
	@echo "$(YELLOW)🧪 Testing:$(RESET)"
	@echo "  $(GREEN)test$(RESET)               - Run all tests"
	@echo "  $(GREEN)test-unit$(RESET)          - Run unit tests only"
	@echo "  $(GREEN)test-integration$(RESET)   - Run integration tests only"
	@echo "  $(GREEN)test-watch$(RESET)         - Run tests in watch mode"
	@echo "  $(GREEN)test-coverage$(RESET)      - Run tests with coverage report"
	@echo "  $(GREEN)test-coverage-unit$(RESET) - Generate unit test coverage report"
	@echo "  $(GREEN)test-coverage-integration$(RESET) - Generate integration test coverage report"
	@echo "  $(GREEN)test-benchmark$(RESET)     - Run benchmark tests"
	@echo "  $(GREEN)test-clean$(RESET)         - Clean test artifacts"
	@echo "  $(GREEN)test-db-setup$(RESET)      - Setup test database"
	@echo "  $(GREEN)test-db-cleanup$(RESET)    - Cleanup test database"
	@echo "  $(GREEN)test-db-reset$(RESET)      - Reset test database"
	@echo ""
	@echo "$(YELLOW)🐳 Docker & Compose:$(RESET)"
	@echo "  $(GREEN)docker-compose-up$(RESET)  - Start all services (PostgreSQL + Grafana Alloy)"
	@echo "  $(GREEN)docker-compose-down$(RESET) - Stop all services"
	@echo "  $(GREEN)docker-compose-restart$(RESET) - Restart all services"
	@echo "  $(GREEN)docker-compose-logs$(RESET) - Show logs from all services"
	@echo "  $(GREEN)docker-compose-logs-postgres$(RESET) - Show PostgreSQL logs"
	@echo "  $(GREEN)docker-compose-logs-alloy$(RESET) - Show Grafana Alloy logs"
	@echo "  $(GREEN)docker-compose-status$(RESET) - Check status of all services"
	@echo "  $(GREEN)docker-build$(RESET)       - Build Docker image"
	@echo "  $(GREEN)docker-run$(RESET)         - Run Docker container"
	@echo "  $(GREEN)docker-stop$(RESET)        - Stop Docker container"
	@echo ""
	@echo "$(YELLOW)🗄️  Database & Migrations:$(RESET)"
	@echo "  $(GREEN)migrate-up$(RESET)         - Run database migrations"
	@echo "  $(GREEN)migrate-down$(RESET)       - Rollback 1 database migration"
	@echo "  $(GREEN)migrate-down-all$(RESET)   - Rollback ALL database migrations (⚠️  destructive)"
	@echo "  $(GREEN)migrate-reset$(RESET)      - Reset database (down all + up)"
	@echo "  $(GREEN)migrate-status$(RESET)     - Show current migration status"
	@echo "  $(GREEN)migrate-goto$(RESET)       - Go to specific migration version"
	@echo "  $(GREEN)migrate-force$(RESET)      - Force set migration version (⚠️  use with caution)"
	@echo "  $(GREEN)migrate-create$(RESET)     - Create a new migration file"
	@echo "  $(GREEN)migrate-validate$(RESET)   - Validate migration files"
	@echo "  $(GREEN)migrate-list$(RESET)       - List all available migrations"
	@echo ""
	@echo "$(YELLOW)🔧 Migration Script (Alternative Interface):$(RESET)"
	@echo "  $(GREEN)migrate-script-help$(RESET) - Show migration script help"
	@echo "  $(GREEN)migrate-script$(RESET)     - Run migration script with arguments"
	@echo ""
	@echo "$(YELLOW)🔒 Security & Monitoring:$(RESET)"
	@echo "  $(GREEN)security$(RESET)           - Run security checks"
	@echo "  $(GREEN)audit$(RESET)              - Run dependency audit"
	@echo "  $(GREEN)health$(RESET)             - Check application health"
	@echo ""
	@echo "$(YELLOW)⚙️  Configuration & CI:$(RESET)"
	@echo "  $(GREEN)setup$(RESET)              - Initial project setup"
	@echo "  $(GREEN)ci$(RESET)                 - Continuous integration pipeline"
	@echo "  $(GREEN)info$(RESET)               - Show project information"
	@echo ""
	@echo "$(BLUE)💡 Quick Start:$(RESET)"
	@echo "  $(GREEN)make setup$(RESET)               - Initial project setup"
	@echo "  $(GREEN)make docker-compose-up$(RESET)   - Start all services (PostgreSQL + Grafana Alloy)"
	@echo "  $(GREEN)make dev$(RESET)                 - Start development server with hot reload"
	@echo "  $(GREEN)make test$(RESET)                - Run all tests"
	@echo ""

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
	~/go/bin/templ generate
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
	$(GOTEST) -bench=. -benchmem -run=^$$ ./tests/... | tee benchmark.out
	@echo "$(BLUE)Generating benchmark HTML report...$(RESET)"
	$(GOCMD) tool pprof -http=localhost:0 -no_browser -output=benchmark.html ./tests/... 2>/dev/null || echo "$(YELLOW)HTML report generation skipped (requires pprof)$(RESET)"
	@echo "$(GREEN)Benchmark tests completed$(RESET)"

## test-clean: Clean test artifacts
test-clean:
	@echo "$(BLUE)Cleaning test artifacts...$(RESET)"
	rm -f coverage*.out coverage*.html benchmark.out benchmark.html loadtest-results.json
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
	$(GOBUILD) $(BUILD_FLAGS) -o bin/$(BINARY_NAME) ./cmd/main.go
	@echo "$(GREEN)Build completed: bin/$(BINARY_NAME)$(RESET)"

## build-prod: Build for production
build-prod: generate format lint test
	@echo "$(BLUE)Building production binary...$(RESET)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -a -installsuffix cgo -o bin/$(BINARY_NAME)-linux-amd64 .
	@echo "$(GREEN)Production build completed$(RESET)"

## dev: Run development server with hot reload
dev: generate docker-compose-up
	@echo "$(BLUE)Starting development server...$(RESET)"
	@if [ -f .env ]; then \
		echo "$(GREEN)✓ Environment loaded from .env file$(RESET)"; \
	else \
		echo "$(YELLOW)⚠ No .env file found, using defaults$(RESET)"; \
	fi
	@if command -v air >/dev/null 2>&1; then \
		$(GOAIR); \
	else \
		echo "$(YELLOW)Air not found, installing...$(RESET)"; \
		$(GOCMD) install github.com/air-verse/air@latest; \
		$(GOAIR); \
	fi

## run: Run the application
run: build
	@echo "$(BLUE)Starting $(PROJECT_NAME)...$(RESET)"
	./bin/$(BINARY_NAME)

## migrate-up: Run database migrations
migrate-up:
	@echo "$(BLUE)Running database migrations...$(RESET)"
	@if ! command -v ~/go/bin/migrate >/dev/null 2>&1; then \
		echo "$(RED)Error: migrate tool not found. Run 'make deps' to install.$(RESET)"; \
		exit 1; \
	fi
	~/go/bin/migrate -path migrations -database "$(DB_URL)" up
	@echo "$(GREEN)Migrations completed$(RESET)"

## migrate-down: Rollback database migrations (rollback 1 step)
migrate-down:
	@echo "$(BLUE)Rolling back 1 database migration...$(RESET)"
	@if ! command -v ~/go/bin/migrate >/dev/null 2>&1; then \
		echo "$(RED)Error: migrate tool not found. Run 'make deps' to install.$(RESET)"; \
		exit 1; \
	fi
	~/go/bin/migrate -path migrations -database "$(DB_URL)" down 1
	@echo "$(GREEN)Rollback completed$(RESET)"

## migrate-down-all: Rollback all database migrations
migrate-down-all:
	@echo "$(RED)WARNING: This will rollback ALL migrations and destroy all data!$(RESET)"
	@read -p "Are you sure? Type 'yes' to confirm: " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		echo "$(BLUE)Rolling back all database migrations...$(RESET)"; \
		~/go/bin/migrate -path migrations -database "$(DB_URL)" down -all; \
		echo "$(GREEN)All migrations rolled back$(RESET)"; \
	else \
		echo "$(YELLOW)Migration rollback cancelled$(RESET)"; \
	fi

## migrate-reset: Reset database (down all + up)
migrate-reset:
	@echo "$(BLUE)Resetting database (down all + up)...$(RESET)"
	@if ! command -v ~/go/bin/migrate >/dev/null 2>&1; then \
		echo "$(RED)Error: migrate tool not found. Run 'make deps' to install.$(RESET)"; \
		exit 1; \
	fi
	~/go/bin/migrate -path migrations -database "$(DB_URL)" down -all
	~/go/bin/migrate -path migrations -database "$(DB_URL)" up
	@echo "$(GREEN)Database reset completed$(RESET)"

## migrate-status: Show migration status
migrate-status:
	@echo "$(BLUE)Checking migration status...$(RESET)"
	@if ! command -v ~/go/bin/migrate >/dev/null 2>&1; then \
		echo "$(RED)Error: migrate tool not found. Run 'make deps' to install.$(RESET)"; \
		exit 1; \
	fi
	~/go/bin/migrate -path migrations -database "$(DB_URL)" version
	@echo "$(GREEN)Migration status check completed$(RESET)"

## migrate-goto: Go to specific migration version
migrate-goto:
	@echo "$(BLUE)Available migrations:$(RESET)"
	@ls -1 migrations/*.up.sql 2>/dev/null | sed 's/migrations\///g' | sed 's/\.up\.sql//g' | sort || echo "$(YELLOW)No migrations found$(RESET)"
	@read -p "Enter migration version to go to (e.g., 000001): " version; \
	if [ -n "$$version" ]; then \
		echo "$(BLUE)Going to migration version $$version...$(RESET)"; \
		migrate -path migrations -database "$(DB_URL)" goto $$version; \
		echo "$(GREEN)Migration to version $$version completed$(RESET)"; \
	else \
		echo "$(YELLOW)No version specified, operation cancelled$(RESET)"; \
	fi

## migrate-force: Force set migration version (use with caution)
migrate-force:
	@echo "$(RED)WARNING: This will force set the migration version without running migrations!$(RESET)"
	@echo "$(YELLOW)This should only be used to fix migration state issues.$(RESET)"
	@read -p "Enter version to force set (e.g., 000001): " version; \
	if [ -n "$$version" ]; then \
		read -p "Are you sure? Type 'yes' to confirm: " confirm; \
		if [ "$$confirm" = "yes" ]; then \
			echo "$(BLUE)Force setting migration version to $$version...$(RESET)"; \
			migrate -path migrations -database "$(DB_URL)" force $$version; \
			echo "$(GREEN)Migration version forced to $$version$(RESET)"; \
		else \
			echo "$(YELLOW)Force migration cancelled$(RESET)"; \
		fi; \
	else \
		echo "$(YELLOW)No version specified, operation cancelled$(RESET)"; \
	fi

## migrate-create: Create a new migration file
migrate-create:
	@if ! command -v migrate >/dev/null 2>&1; then \
		echo "$(RED)Error: migrate tool not found. Run 'make deps' to install.$(RESET)"; \
		exit 1; \
	fi
	@read -p "Enter migration name (e.g., add_user_profile_table): " name; \
	if [ -n "$$name" ]; then \
		migrate create -ext sql -dir migrations $$name; \
		echo "$(GREEN)Migration files created for: $$name$(RESET)"; \
		echo "$(BLUE)Edit the generated .up.sql and .down.sql files in the migrations/ directory$(RESET)"; \
	else \
		echo "$(YELLOW)No migration name specified, operation cancelled$(RESET)"; \
	fi

## migrate-validate: Validate migration files
migrate-validate:
	@echo "$(BLUE)Validating migration files...$(RESET)"
	@if [ ! -d "migrations" ]; then \
		echo "$(RED)Error: migrations directory not found$(RESET)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Checking for .up.sql files...$(RESET)"
	@up_count=$$(ls -1 migrations/*.up.sql 2>/dev/null | wc -l); \
	down_count=$$(ls -1 migrations/*.down.sql 2>/dev/null | wc -l); \
	echo "Found $$up_count up migrations and $$down_count down migrations"; \
	if [ $$up_count -eq $$down_count ]; then \
		echo "$(GREEN)✓ Migration file counts match$(RESET)"; \
	else \
		echo "$(RED)✗ Migration file counts don't match$(RESET)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Checking for matching up/down pairs...$(RESET)"
	@for up_file in migrations/*.up.sql; do \
		base_name=$$(basename "$$up_file" .up.sql); \
		down_file="migrations/$$base_name.down.sql"; \
		if [ -f "$$down_file" ]; then \
			echo "$(GREEN)✓ $$base_name$(RESET)"; \
		else \
			echo "$(RED)✗ Missing down migration for $$base_name$(RESET)"; \
			exit 1; \
		fi; \
	done
	@echo "$(GREEN)All migration files are valid$(RESET)"

## migrate-list: List all available migrations
migrate-list:
	@echo "$(BLUE)Available migrations:$(RESET)"
	@if [ -d "migrations" ]; then \
		for file in migrations/*.up.sql; do \
			if [ -f "$$file" ]; then \
				base_name=$$(basename "$$file" .up.sql); \
				migration_name=$$(echo "$$base_name" | sed 's/^[0-9]*_//'); \
				echo "  $(GREEN)$$base_name$(RESET) - $$migration_name"; \
			fi; \
		done; \
	else \
		echo "$(YELLOW)No migrations directory found$(RESET)"; \
	fi

## migrate-tool-up: Use built-in migration tool to run up migrations
migrate-tool-up:
	@echo "$(BLUE)Running migrations with built-in tool...$(RESET)"
	$(GOCMD) run cmd/migrate/main.go -command up
	@echo "$(GREEN)Built-in migration tool completed$(RESET)"

## migrate-tool-down: Use built-in migration tool to rollback migrations
migrate-tool-down:
	@echo "$(BLUE)Rolling back migrations with built-in tool...$(RESET)"
	$(GOCMD) run cmd/migrate/main.go -command down
	@echo "$(GREEN)Built-in migration rollback completed$(RESET)"

## migrate-tool-status: Use built-in migration tool to check status
migrate-tool-status:
	@echo "$(BLUE)Checking migration status with built-in tool...$(RESET)"
	$(GOCMD) run cmd/migrate/main.go -command version

## migrate-tool-create: Use built-in migration tool to create migration
migrate-tool-create:
	@read -p "Enter migration name: " name; \
	if [ -n "$$name" ]; then \
		$(GOCMD) run cmd/migrate/main.go -command create -name "$$name"; \
	else \
		echo "$(YELLOW)No migration name specified$(RESET)"; \
	fi

## migrate-script-help: Show migration script help
migrate-script-help:
	@./scripts/migrate.sh --help

## migrate-script: Run migration script with arguments (usage: make migrate-script ARGS="command options")
migrate-script:
	@if [ -z "$(ARGS)" ]; then \
		echo "$(YELLOW)Usage: make migrate-script ARGS=\"command options\"$(RESET)"; \
		echo "$(BLUE)Examples:$(RESET)"; \
		echo "  make migrate-script ARGS=\"list\""; \
		echo "  make migrate-script ARGS=\"up\""; \
		echo "  make migrate-script ARGS=\"create add_new_table\""; \
		echo "  make migrate-script ARGS=\"status\""; \
	else \
		./scripts/migrate.sh $(ARGS); \
	fi

## audit: Run security audit with govulncheck
audit:
	@echo "$(BLUE)Running security audit...$(RESET)"
	@if ! command -v govulncheck >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing govulncheck...$(RESET)"; \
		$(GOCMD) install golang.org/x/vuln/cmd/govulncheck@latest; \
	fi
	govulncheck ./...
	@echo "$(GREEN)Security audit completed$(RESET)"

## security: Run comprehensive security checks
security:
	@echo "$(BLUE)Running security checks...$(RESET)"
	@if ! command -v gosec >/dev/null 2>&1; then \
	    echo "$(YELLOW)Installing gosec...$(RESET)"; \
	    $(GOCMD) install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
	fi
	gosec -fmt=json -out=gosec-report.json -stdout ./...
	@echo "$(GREEN)Security checks completed$(RESET)"

## security-fix: Fix security issues automatically where possible
security-fix:
	@echo "$(BLUE)Attempting to fix security issues...$(RESET)"
	$(GOCMD) mod tidy
	$(GOCMD) get -u all
	@echo "$(GREEN)Security fixes applied$(RESET)"

## security-report: Generate comprehensive security report
security-report: security audit
	@echo "$(BLUE)Generating security report...$(RESET)"
	@echo "Security scan completed on $$(date)" > security-report.txt
	@echo "=======================================" >> security-report.txt
	@if [ -f gosec-report.json ]; then \
	    echo "Gosec findings:" >> security-report.txt; \
	    cat gosec-report.json >> security-report.txt; \
	fi
	@echo "$(GREEN)Security report generated: security-report.txt$(RESET)"

## docker-compose-up: Start all services (PostgreSQL + Grafana Alloy)
docker-compose-up:
	@echo "$(BLUE)Starting all services with Docker Compose...$(RESET)"
	docker compose up -d
	@echo "$(GREEN)All services started successfully$(RESET)"
	@echo "$(YELLOW)PostgreSQL available on: localhost:5432$(RESET)"
	@echo "$(YELLOW)Grafana Alloy UI: http://localhost:12345$(RESET)"

## docker-compose-down: Stop all services
docker-compose-down:
	@echo "$(BLUE)Stopping all services...$(RESET)"
	docker compose down
	@echo "$(GREEN)All services stopped$(RESET)"

## docker-compose-restart: Restart all services
docker-compose-restart: docker-compose-down docker-compose-up
	@echo "$(GREEN)All services restarted$(RESET)"

## docker-compose-logs: Show logs from all services
docker-compose-logs:
	@echo "$(BLUE)Showing logs from all services...$(RESET)"
	docker compose logs -f

## docker-compose-logs-postgres: Show PostgreSQL logs
docker-compose-logs-postgres:
	@echo "$(BLUE)Showing PostgreSQL logs...$(RESET)"
	docker compose logs -f postgres

## docker-compose-logs-alloy: Show Grafana Alloy logs
docker-compose-logs-alloy:
	@echo "$(BLUE)Showing Grafana Alloy logs...$(RESET)"
	docker compose logs -f alloy

## docker-compose-status: Check status of all services
docker-compose-status:
	@echo "$(BLUE)Checking service status...$(RESET)"
	docker compose ps

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
setup: deps generate docker-compose-up migrate-up
	@echo "$(GREEN)Project setup completed$(RESET)"
	@echo "$(YELLOW)Services running:$(RESET)"
	@echo "  - PostgreSQL: localhost:5432"
	@echo "  - Grafana Alloy: http://localhost:12345"
	@echo "$(BLUE)Next steps:$(RESET)"
	@echo "  1. Copy .env.example to .env and configure"
	@echo "  2. Run 'make dev' to start development server"

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