# Fetch dependencies
FROM golang:latest AS fetch-stage
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

# Generate templates and Build the Go binary
FROM golang:latest AS build-stage
WORKDIR /app
COPY . .
RUN go run github.com/a-h/templ/cmd/templ generate
RUN go build -o app main.go

# Deploy
FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=build-stage /app/app /app
EXPOSE 8080
ENTRYPOINT ["/app"]