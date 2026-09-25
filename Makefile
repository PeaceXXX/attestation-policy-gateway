BINARY := gateway
IMAGE := attestation-policy-gateway:latest
GO := go

.PHONY: build test run docker-build clean tidy vet

build:
	$(GO) build -o $(BINARY) ./cmd/gateway

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

run: build
	./$(BINARY) --addr :8080 --data-dir data

docker-build:
	docker build -t $(IMAGE) .

clean:
	rm -f $(BINARY)
	rm -rf data/*.json data/*.jsonl

tidy:
	$(GO) mod tidy
