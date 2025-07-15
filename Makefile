.PHONY: lint test build run tidy

lint:
	docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:v2.2.2 golangci-lint run ./src

test:
	go test -race -v ./...

build:
	go build -o bin/askfrank ./src

run:
	go run ./src/main.go

tidy:
	go mod tidy