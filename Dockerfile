# Build stage
FROM golang:1.25.1-alpine AS builder

WORKDIR /app

# Install ca-certificates and security updates
RUN apk --no-cache add ca-certificates git && \
    apk upgrade --no-cache

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the binary with security flags
RUN CGO_ENABLED=0 GOOS=linux go build \
    -a -installsuffix cgo \
    -ldflags="-w -s -extldflags '-static'" \
    -trimpath \
    -o main .

# Final stage
FROM scratch

# Copy CA certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary from builder stage
COPY --from=builder /app/main /app/main

# Use non-root user (numeric UID for scratch image)
USER 65534:65534

# Expose port
EXPOSE 8080

# Command to run
ENTRYPOINT ["/app/main"]
