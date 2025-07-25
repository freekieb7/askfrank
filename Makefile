default: help

.PHONY: help lint test build run tidy docker-build docker-run docker-clean

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  help         Show this help message"
	@echo "  lint         Run golangci-lint in Docker"
	@echo "  test         Run Go tests with race detector"
	@echo "  build        Build the binary to bin/askfrank"
	@echo "  run          Run the application"
	@echo "  tidy         Run go mod tidy"
	@echo "  docker-build Build the Docker image"
	@echo "  docker-run   Run the Docker container (port 3000)"
	@echo "  docker-clean Remove the Docker image"

lint:
	go vet ./...
	docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:v2.2.2 golangci-lint run ./...

fmt:
	go fmt ./...

test:
	go test -race -v ./...

run:
	go run main.go

tidy:
	go mod tidy

up:
	docker compose up -d

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f

templ-gen:
	go tool templ generate

hot-reload:
	go tool templ generate --watch --proxy="http://localhost:8080" --cmd="go run ."