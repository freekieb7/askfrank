.PHONY: dev tailwind tailwind-minify air 
.PHONY: migrate-build openfga-build
.PHONY: docker-compose-up docker-compose-down docker-compose-restart

# Tailwind
gen-css:
	npx @tailwindcss/cli -i ./internal/web/static/css/components.css -o ./internal/web/static/css/stylesheet.css --minify --optimize

gen-css-dev:
	npx @tailwindcss/cli -i ./internal/web/static/css/components.css -o ./internal/web/static/css/stylesheet.css --watch

gen-docs:
	npx @redocly/cli build-docs ./docs/openapi.yaml -o ./internal/web/static/html/docs.html

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

openfga-build:
	@echo "Building OpenFGA CLI..."
	go build -o bin/openfga ./cmd/openfga

dev: docker-compose-up air

ngrok:
	ngrok http 3001