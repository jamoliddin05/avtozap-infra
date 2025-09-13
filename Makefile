# Makefile for generating .env and running Docker Compose from root

SHELL := /bin/bash

# List of services (submodules)
SERVICES := auth

.PHONY: all env up clean

# Default: generate .env and run all services
all: env up

# Generate .env for all services
env:
	@for s in $(SERVICES); do \
		var_name="$${s^^}_SERVICE_SECRETS"; \
		env_file=./services/$$s/.env; \
		if [ -z "$${!var_name}" ]; then \
			echo "ERROR: GitHub secret $$var_name not set for service $$s"; \
			exit 1; \
		fi; \
		echo "Generating $$env_file from $$var_name..."; \
		echo "$${!var_name}" > $$env_file; \
	done
	@echo "All .env files generated!"

# Clean .env files
clean:
	@for s in $(SERVICES); do \
		echo "Removing ./services/$$s/.env..."; \
		rm -f ./services/$$s/.env; \
	done

# Run migrations UP inside auth container
auth-migrate-up:
	docker compose exec auth \
	sh -c 'migrate -path ./migrations -database "postgres://$${POSTGRES_USER}:$${POSTGRES_PASSWORD}@$${POSTGRES_HOST}:$${POSTGRES_PORT}/$${POSTGRES_DB}?sslmode=$${POSTGRES_SSLMODE}" up'

# Run migrations DOWN inside auth container
auth-migrate-down:
	docker compose exec auth \
	sh -c 'migrate -path ./migrations -database "postgres://$${POSTGRES_USER}:$${POSTGRES_PASSWORD}@$${POSTGRES_HOST}:$${POSTGRES_PORT}/$${POSTGRES_DB}?sslmode=$${POSTGRES_SSLMODE}" down'

