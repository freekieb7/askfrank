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
	docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:v2.2.2 golangci-lint run ./...

test:
	go test -race -v ./...

build:
	go build -o bin/askfrank main.go

run:
	go run main.go

tidy:
	go mod tidy

docker-build:
	docker build -t askfrank .

docker-run:
	docker run --rm -p 3000:3000 askfrank

docker-clean:
	docker rmi askfrank || true

templ-gen:
	go tool templ generate