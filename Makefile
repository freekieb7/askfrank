GOPATH := $(shell go env GOPATH)
ENV_ARGS := $(shell grep -v '^#' .env | xargs)

# Run both Tailwind and Air in parallel
.PHONY: dev
dev: up
	@echo "Starting Tailwind and Air..."
	$(MAKE) gen-css-dev & \
	$(MAKE) air & \
	wait

.PHONY: up
up:
	@echo "Starting Docker containers..."
	docker compose up -d --remove-orphans
	@echo "Docker containers started."

.PHONY: down
down:
	@echo "Stopping Docker containers..."
	docker compose down
	@echo "Docker containers stopped."

.PHONY: restart
restart: down up

# Migration commands
.PHONY: migrate-build
migrate-build:
	@echo "Building migration CLI..."
	go build -o bin/migrate ./cmd/migrate

.PHONY: migrate-up
migrate-up:
	${ENV_ARGS} go run ./cmd/migrate up

.PHONY: migrate-down
migrate-down:
	${ENV_ARGS} go run ./cmd/migrate down

# Go dev mode with Air
.PHONY: air
air:
	go install github.com/air-verse/air@latest
	${GOPATH}/bin/air -c .air.toml

# Ngrok
.PHONY: ngrok
ngrok:
	ngrok http 3001

# Templating
.PHONY: gen-templates
gen-templates:
	go install github.com/a-h/templ/cmd/templ@latest
	${GOPATH}/bin/templ generate

# Tailwind
.PHONY: gen-css
gen-css:
	npx @tailwindcss/cli -i ./internal/web/page/static/css/components.css -o ./internal/web/page/static/css/stylesheet.css --minify --optimize

.PHONY: gen-css-dev
gen-css-dev:
	npx @tailwindcss/cli -i ./internal/web/page/static/css/components.css -o ./internal/web/page/static/css/stylesheet.css --watch

.PHONY: gen-docs
gen-docs:
	npx @redocly/cli build-docs ./docs/openapi.yaml -o ./internal/web/page/static/html/docs.html