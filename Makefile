.PHONY: dev tailwind tailwind-minify air
.PHONY: docker-compose-up docker-compose-down docker-compose-restart

# Tailwind dev mode
tailwind:
	npx @tailwindcss/cli -c tailwind.config.js -i ./internal/web/static/input.css -o ./internal/web/static/output.css

# Tailwind build for production
tailwind-minify:
	npx @tailwindcss/cli -i ./internal/web/static/input.css -o ./internal/web/static/output.css --minify

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

dev: docker-compose-up tailwind air