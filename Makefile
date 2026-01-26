.PHONY: build run test clean up down logs

build:
	go build -o bin/proxy cmd/proxy/main.go

run:
	go run cmd/proxy/main.go

test:
	go test -v ./...

clean:
	rm -rf bin/

up:
	docker-compose up -d

down:
	docker-compose down

logs:
	docker-compose logs -f proxy

fmt:
	go fmt ./...