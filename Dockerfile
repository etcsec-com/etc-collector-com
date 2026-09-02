# Build stage
# go.mod exige `go 1.26.7` : une image plus ancienne fait echouer `go mod download`
# des la ligne 11 (run 33446672192). Garder cette version alignee sur go.mod.
FROM golang:1.26-alpine AS builder

# Install certificates and git
RUN apk add --no-cache ca-certificates git

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# T_097: the binary used to report whatever main.Version is hardcoded to
# in-source (currently 3.1.39) regardless of what tag this image is built or
# named as — `docker build --build-arg VERSION=3.2.0 .` (or the release
# pipeline passing the real tag) now reaches `etc-collector --version` and
# every /health response. Defaults to "dev" so a bare `docker build .` still
# clearly says "not a numbered release" instead of silently claiming 3.1.39.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s -X main.Version=${VERSION}" -o etc-collector ./cmd/etc-collector

# Runtime stage
FROM alpine:3.19

# Install certificates for TLS
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 collector && \
    adduser -u 1000 -G collector -D collector

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/etc-collector .

# Create data directory
RUN mkdir -p /app/data /app/keys && \
    chown -R collector:collector /app

# Switch to non-root user
USER collector

# Expose API port
EXPOSE 8443

# Health check. T_097: CMD's own --host 0.0.0.0 (below) makes the server
# auto-provision a self-signed certificate and serve HTTPS only — a plain
# http:// probe against it gets "HTTP/1.0 400 Bad Request" (confirmed live),
# so the container would sit at STATUS "unhealthy" forever despite serving
# requests correctly. --no-check-certificate: this probe runs inside the
# same container as the server it's checking, so there's no MITM surface to
# defend against — it only needs to know the process answers.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --no-check-certificate --spider https://localhost:8443/health || exit 1

# Default command.
#
# T_097: `server` alone used to crash the container outright, even with a
# real config.yaml mounted — its default config directory is /etc/etc-collector
# (root.go), unwritable by the non-root `collector` user this image runs as
# (confirmed live: "mkdir /etc/etc-collector: permission denied", fatal,
# before the API server ever starts). --config-dir /app points it at the
# directory this image already creates and chowns to collector above.
#
# --host 0.0.0.0 is also required, not cosmetic: the server flag's own
# default is 127.0.0.1 (sane for a bare-metal install), which inside a
# container means EXPOSE 8443 and a mapped port would never be reachable —
# the container looks "up" (its own healthcheck runs inside the container's
# network namespace, so it passes) while every request from the host times
# out. A non-loopback --host auto-provisions a self-signed TLS certificate
# (see server.go) — reachable at https://localhost:8443, browser warns once.
ENTRYPOINT ["/app/etc-collector"]
CMD ["server", "--host", "0.0.0.0", "--config-dir", "/app"]
