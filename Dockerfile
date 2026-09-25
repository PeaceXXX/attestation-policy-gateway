# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
# stdlib-only module: nothing to download, but keep the layer for future deps
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /gateway ./cmd/gateway

# ---- run ----
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /gateway /app/gateway
# Data dir holds policies.json and audit.jsonl
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/gateway", "--addr", ":8080", "--data-dir", "/data"]
