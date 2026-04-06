# Constellation Protocol PoC — Multi-stage build
#
# Build:   docker build -t constellation-poc:dev .
# Run:     docker run -p 8100:8100 constellation-poc:dev node --name alpha --port 8100

# -- Stage 1: Build --
FROM golang:1.24-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /constellation-poc .

# -- Stage 2: Runtime --
FROM alpine:3.21

RUN apk add --no-cache ca-certificates git curl

RUN addgroup -S constellation && adduser -S constellation -G constellation

WORKDIR /data

COPY --from=builder /constellation-poc /usr/local/bin/constellation-poc

RUN mkdir -p /data && chown -R constellation:constellation /data

USER constellation

EXPOSE 8100

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -sf http://localhost:8100/health || exit 1

ENTRYPOINT ["constellation-poc"]
CMD ["node", "--name", "default", "--port", "8100"]
