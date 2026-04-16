FROM golang:1.22-alpine AS builder

ARG VERSION=docker

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X github.com/vikram290227/fhir-privacy-proxy/internal/tracing.ServiceVersion=${VERSION}" \
    -o proxy ./cmd/proxy

FROM alpine:latest

RUN apk --no-cache add ca-certificates curl

WORKDIR /app

COPY --from=builder /app/proxy .

EXPOSE 8080

CMD ["./proxy"]