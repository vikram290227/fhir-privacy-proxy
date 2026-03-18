.PHONY: build run test test-cover clean up down logs fmt lint

build:
	go build -o bin/proxy cmd/proxy/main.go

run:
	go run cmd/proxy/main.go

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
