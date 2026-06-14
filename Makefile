.PHONY: build run test test-cover test-public bench bench-fixtures clean up down logs fmt lint

# Stamp the build with a service.version attribute that shows up in
# Jaeger / any OTLP collector. Falls back to a git-describe-ish string
# so unreleased dev builds can still be distinguished.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/vikram290227/fhir-privacy-proxy/internal/tracing.ServiceVersion=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o bin/proxy cmd/proxy/main.go

run:
	go run -ldflags "$(LDFLAGS)" cmd/proxy/main.go

test:
	go test -v ./...

test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

test-public:
	@echo "=== Starting stack with public HAPI upstream ==="
	FHIR_UPSTREAM=http://hapi.fhir.org/baseR4 \
		docker-compose -f deployments/docker/docker-compose.yml up -d
	@echo "Waiting for proxy health..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
		if curl -sf http://localhost:8080/health > /dev/null 2>&1; then \
			echo "Proxy is healthy"; \
			break; \
		fi; \
		echo "  waiting... ($$i/15)"; \
		sleep 4; \
	done
	@echo "Waiting for Keycloak..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
		if curl -sf http://localhost:8180/realms/hospital-a > /dev/null 2>&1; then \
			echo "Keycloak is ready"; \
			break; \
		fi; \
		echo "  waiting... ($$i/15)"; \
		sleep 4; \
	done
	./scripts/public_api_smoke.sh

clean:
	rm -rf bin/ coverage.out coverage.html

up:
	docker-compose -f deployments/docker/docker-compose.yml up -d

down:
	docker-compose -f deployments/docker/docker-compose.yml down

logs:
	docker-compose -f deployments/docker/docker-compose.yml logs -f proxy

fmt:
	go fmt ./...

lint:
	go vet ./...

bench:
	go test -bench=BenchmarkRedaction -benchmem -benchtime=3s ./internal/fhir/...

bench-fixtures:
	./scripts/generate_bench_fixtures.sh
