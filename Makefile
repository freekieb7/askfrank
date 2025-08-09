.PHONY: dev tailwind tailwind-minify air migrate-up migrate-down migrate-version migrate-health migrate-build migrate-status migrate-create migrate-validate migrate-dry-run
.PHONY: docker-compose-up docker-compose-down docker-compose-restart

# Tailwind dev mode
tailwind:
	npx tailwindcss -c tailwind.config.js -i ./internal/web/static/css/input.css -o ./internal/web/static/css/tailwind.css

# Tailwind build for production
tailwind-minify:
	npx tailwindcss -i ./internal/web/static/css/input.css -o ./internal/web/static/css/tailwind.css --minify

# Go dev mode with Air
air:
	go tool air -c .air.toml

# Run both Tailwind and Air in parallel
dev: docker-compose-up
	@echo "Starting Tailwind and Air..."
	$(MAKE) tailwind & \
	$(MAKE) air & \
	wait

docker-compose-up:
	@echo "Starting Docker containers..."
	docker compose up -d --remove-orphans
	@echo "Docker containers started."

docker-compose-down:
	@echo "Stopping Docker containers..."
	docker compose down
	@echo "Docker containers stopped."

docker-compose-restart: docker-compose-down docker-compose-up

# Migration commands
migrate-build:
	@echo "Building migration CLI..."
	go build -o bin/migrate ./cmd/migrate

migrate-up: migrate-build
	@echo "Running migrations up..."
	./bin/migrate up

migrate-down: migrate-build
	@echo "Running migrations down..."
	./bin/migrate down

migrate-version: migrate-build
	@echo "Getting migration version..."
	./bin/migrate version

migrate-health: migrate-build
	@echo "Checking database health..."
	./bin/migrate health

migrate-status: migrate-build
	@echo "Getting migration status..."
	./bin/migrate status

migrate-create: migrate-build
	@echo "Usage examples:"
	@echo "  ./bin/migrate create <migration_name>"
	@echo "Example: ./bin/migrate create add_user_profiles"

migrate-validate: migrate-build
	@echo "Validating migrations..."
	./bin/migrate validate

migrate-enhanced-validate: migrate-build
	@echo "Running enhanced validation..."
	./bin/migrate enhanced-validate

migrate-dry-run: migrate-build
	@echo "Usage examples:"
	@echo "  ./bin/migrate dry-run up"
	@echo "  ./bin/migrate dry-run down --steps 2"

migrate-to: migrate-build
	@echo "Usage examples:"
	@echo "  ./bin/migrate migrate-to <version>"
	@echo "Example: ./bin/migrate migrate-to 20240101000000"

migrate-drift-check: migrate-build
	@echo "Checking for schema drift..."
	./bin/migrate drift-check

dev: docker-compose-up tailwind air