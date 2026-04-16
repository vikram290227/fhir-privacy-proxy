.PHONY: build run test test-cover clean up down logs fmt lint

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
