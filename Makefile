.PHONY: up down logs restart clean build deploy dev

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

restart: down up

clean:
	docker compose down -v --remove-orphans

build:
	docker compose build

deploy:
	git pull
	docker compose up -d --build

# Локально с публикацией порта 8001
dev:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
