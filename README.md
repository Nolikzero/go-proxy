# Go HTTP/HTTPS Proxy Server

A production-ready HTTP/HTTPS proxy server built in Go with enterprise features including authentication, host filtering, structured logging, and graceful shutdown.

## Features

- 🚀 **High Performance**: Optimized HTTP client with connection pooling and HTTP/2 support
- 🔒 **Security**: Basic authentication, host allowlist/blocklist, TLS support, and rate limiting
- 📊 **Observability**: Structured JSON logging, Prometheus metrics, and health checks
- 🐳 **Production Ready**: Docker support, graceful shutdown, comprehensive testing, and configuration validation
- 🌐 **Protocol Support**: HTTP and HTTPS tunneling (CONNECT method)
- ⚙️ **Configurable**: Environment-based configuration with sensible defaults
- 🛡️ **Rate Limiting**: Per-IP token bucket rate limiting to prevent abuse
- 📈 **Metrics**: Built-in Prometheus metrics for monitoring and alerting

## Quick Start

### Option 1: Run with Go

```bash
# Clone and build
git clone <repository-url>
cd go-proxy
go mod download
go run .
```

### Option 2: Run with Docker

```bash
# Build and run
docker build -t go-proxy .
docker run -p 8080:8080 go-proxy
```

### Option 3: Run with Docker Compose

```bash
# Start the service
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

## Configuration

The proxy server is configured through environment variables. All configuration options have sensible defaults.

### Server Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PROXY_PORT` | `8080` | Server port |
| `PROXY_HOST` | `` | Server host (empty = all interfaces) |
| `PROXY_READ_TIMEOUT` | `30s` | HTTP read timeout |
| `PROXY_WRITE_TIMEOUT` | `30s` | HTTP write timeout |
| `PROXY_IDLE_TIMEOUT` | `120s` | HTTP idle timeout |

### TLS Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PROXY_ENABLE_TLS` | `false` | Enable TLS for the proxy server |
| `PROXY_TLS_CERT_FILE` | `` | Path to TLS certificate file |
| `PROXY_TLS_KEY_FILE` | `` | Path to TLS private key file |
| `PROXY_TLS_MIN_VERSION` | `1.2` | Minimum TLS version (1.2 or 1.3) |

### Proxy Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PROXY_ENABLE_HTTPS` | `true` | Enable HTTPS tunneling (CONNECT method) |
| `PROXY_CONNECT_TIMEOUT` | `10s` | Connection timeout for upstream servers |
| `PROXY_MAX_IDLE_CONNS` | `100` | Maximum idle connections |
| `PROXY_MAX_IDLE_CONNS_PER_HOST` | `10` | Maximum idle connections per host |

### Security Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PROXY_REQUIRE_AUTH` | `false` | Enable basic authentication |
| `PROXY_AUTH_USER` | `` | Username for basic auth |
| `PROXY_AUTH_PASSWORD` | `` | Password for basic auth (min 8 characters) |
| `PROXY_ENFORCE_AUTH_TLS` | `true` | Require TLS when authentication is enabled |
| `PROXY_ALLOWED_HOSTS` | `` | Comma-separated list of allowed hosts |
| `PROXY_BLOCKED_HOSTS` | `` | Comma-separated list of blocked hosts |
| `PROXY_MAX_HEADER_BYTES` | `1048576` | Maximum header size (1MB) |
| `PROXY_MAX_BODY_BYTES` | `10485760` | Maximum request/response body size (10MB) |

### Rate Limiting Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PROXY_ENABLE_RATE_LIMIT` | `true` | Enable per-IP rate limiting |
| `PROXY_RATE_LIMIT_RPS` | `100` | Requests per second per IP |
| `PROXY_RATE_LIMIT_BURST` | `200` | Maximum burst capacity per IP |

### Logging Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PROXY_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `PROXY_LOG_FORMAT` | `json` | Log format (json, text) |

## Usage Examples

### Basic Usage

Start the proxy on port 8080:

```bash
go run .
```

Configure your HTTP client to use `http://localhost:8080` as the proxy.

### With Authentication

```bash
export PROXY_REQUIRE_AUTH=true
export PROXY_AUTH_USER=admin
export PROXY_AUTH_PASSWORD=secret123
go run .
```

Configure your HTTP client to use proxy authentication.

### With Host Filtering

Allow only specific hosts:

```bash
export PROXY_ALLOWED_HOSTS=example.com,api.example.com,google.com
go run .
```

Block specific hosts:

```bash
export PROXY_BLOCKED_HOSTS=malicious.com,spam.example.org
go run .
```

### With TLS

```bash
export PROXY_ENABLE_TLS=true
export PROXY_TLS_CERT_FILE=/path/to/server.crt
export PROXY_TLS_KEY_FILE=/path/to/server.key
export PROXY_PORT=8443
go run .
```

### Production Configuration

```bash
export PROXY_PORT=3128
export PROXY_REQUIRE_AUTH=true
export PROXY_AUTH_USER=proxyuser
export PROXY_AUTH_PASSWORD=secure_password
export PROXY_ENFORCE_AUTH_TLS=true
export PROXY_ENABLE_TLS=true
export PROXY_TLS_CERT_FILE=/path/to/cert.pem
export PROXY_TLS_KEY_FILE=/path/to/key.pem
export PROXY_TLS_MIN_VERSION=1.3
export PROXY_ALLOWED_HOSTS=trusted.com,api.trusted.com
export PROXY_ENABLE_RATE_LIMIT=true
export PROXY_RATE_LIMIT_RPS=100
export PROXY_RATE_LIMIT_BURST=200
export PROXY_MAX_BODY_BYTES=10485760
export PROXY_LOG_LEVEL=info
export PROXY_LOG_FORMAT=json
export PROXY_MAX_IDLE_CONNS=200
export PROXY_MAX_IDLE_CONNS_PER_HOST=20
go run .
```

## Client Configuration

### cURL

```bash
# HTTP proxy
curl -x http://localhost:8080 http://example.com

# With authentication
curl -x http://admin:secret123@localhost:8080 http://example.com

# HTTPS through proxy (tunneling)
curl -x http://localhost:8080 https://example.com
```

### Browser Configuration

1. Open browser proxy settings
2. Set HTTP proxy to `localhost:8080`
3. Set HTTPS proxy to `localhost:8080` (for CONNECT tunneling)
4. If authentication is enabled, provide credentials when prompted

### Programming Languages

#### Python (requests)

```python
import requests

proxies = {
    'http': 'http://localhost:8080',
    'https': 'http://localhost:8080'
}

# With authentication
proxies_auth = {
    'http': 'http://admin:secret123@localhost:8080',
    'https': 'http://admin:secret123@localhost:8080'
}

response = requests.get('http://example.com', proxies=proxies)
```

#### Node.js

```javascript
const axios = require('axios');

const config = {
  proxy: {
    host: 'localhost',
    port: 8080,
    auth: {  // if authentication is enabled
      username: 'admin',
      password: 'secret123'
    }
  }
};

axios.get('http://example.com', config);
```

## Development

### Build

```bash
go build -o go-proxy .
```

### Test

```bash
# Run all tests
go test -v .

# Run tests with coverage
go test -v -cover .

# Run specific test
go test -v -run TestRateLimiter
```

### Run with Make

```bash
# Build the project
make build

# Run the project
make run

# Run tests
make test

# Clean build artifacts
make clean

# Build Docker image
make docker-build

# Run with Docker
make docker-run
```

## Deployment

### Docker

```bash
# Build image
docker build -t go-proxy:latest .

# Run container
docker run -d \
  --name go-proxy \
  -p 8080:8080 \
  -e PROXY_REQUIRE_AUTH=true \
  -e PROXY_AUTH_USER=admin \
  -e PROXY_AUTH_PASSWORD=secret123 \
  go-proxy:latest
```

### Docker Compose

See `docker-compose.yml` for a complete deployment example with all configuration options.

### Systemd Service

Create `/etc/systemd/system/go-proxy.service`:

```ini
[Unit]
Description=Go HTTP/HTTPS Proxy Server
After=network.target

[Service]
Type=simple
User=proxy
WorkingDirectory=/opt/go-proxy
ExecStart=/opt/go-proxy/go-proxy
Restart=always
RestartSec=5
Environment=PROXY_PORT=3128
Environment=PROXY_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl enable go-proxy
sudo systemctl start go-proxy

# Check status
sudo systemctl status go-proxy

# View logs
sudo journalctl -u go-proxy -f
```

## Monitoring

### Health Check

Use the dedicated `/healthz` or `/health` endpoint for container orchestrators or load balancers:

```bash
curl http://localhost:8080/healthz
```

### Metrics Endpoint

Prometheus metrics are available at `/metrics`:

```bash
curl http://localhost:8080/metrics
```

**Available Metrics:**
- `proxy_requests_total` - Total requests by method and status code
- `proxy_request_duration_seconds` - Request duration histogram by method
- `proxy_requests_in_flight` - Current number of requests being processed
- `proxy_tunnels_active` - Current number of active HTTPS tunnels
- `proxy_bytes_transferred_total` - Total bytes transferred (inbound/outbound)
- `proxy_rate_limit_exceeded_total` - Rate limit violations by IP
- `proxy_auth_failures_total` - Authentication failures
- `proxy_host_blocked_total` - Blocked host access attempts
- `proxy_upstream_errors_total` - Upstream connection errors by type

### Logs

The proxy generates structured JSON logs (configurable) with the following fields:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "message": "HTTP request",
  "method": "GET",
  "url": "http://example.com",
  "status": 200,
  "duration": "150ms",
  "remote_ip": "192.168.1.100",
  "user_agent": "curl/7.68.0"
}
```

### Metrics

Monitor these key metrics:
- Request count and rate
- Response status codes
- Request duration
- Connection count
- Error rate

## Security Considerations

1. **Authentication**: Always enable authentication in production with strong passwords (min 8 characters)
2. **TLS Enforcement**: Enable `PROXY_ENFORCE_AUTH_TLS` to require TLS when auth is enabled
3. **Host Filtering**: Use allowlist for maximum security
4. **TLS**: Enable TLS 1.3 for the proxy server in production
5. **Rate Limiting**: Enable rate limiting to prevent abuse and DDoS attacks
6. **Body Size Limits**: Configure appropriate body size limits for your use case
7. **Access Control**: Run with minimal privileges (non-root user)
8. **Network**: Deploy in a secure network environment
9. **Monitoring**: Monitor logs and metrics for suspicious activity
10. **Configuration Validation**: The proxy validates all configuration on startup

## Performance Tuning

### Connection Pooling

Adjust connection pool settings for your use case:

```bash
export PROXY_MAX_IDLE_CONNS=500
export PROXY_MAX_IDLE_CONNS_PER_HOST=50
```

### Timeouts

Tune timeouts for your network conditions:

```bash
export PROXY_CONNECT_TIMEOUT=5s
export PROXY_READ_TIMEOUT=60s
export PROXY_WRITE_TIMEOUT=60s
```

### Resource Limits

Set appropriate resource limits:

```bash
export PROXY_MAX_HEADER_BYTES=2097152  # 2MB
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Check if the proxy is running and port is accessible
2. **Authentication Errors**: Verify credentials and ensure auth is enabled
3. **Host Blocked**: Check allowed/blocked hosts configuration
4. **TLS Errors**: Verify certificate files and paths
5. **Timeout Errors**: Adjust timeout settings for your network

### Debug Mode

Enable debug logging:

```bash
export PROXY_LOG_LEVEL=debug
go run .
```

### Network Issues

Test connectivity:

```bash
# Test proxy connectivity
curl -v -x http://localhost:8080 http://example.com

# Test direct connectivity
curl -v http://example.com
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Documentation

- **[CODE_REVIEW.md](CODE_REVIEW.md)** - Comprehensive code review and improvements summary
- **[PRODUCTION.md](PRODUCTION.md)** - Production deployment guide with security, monitoring, and HA setup
- **README.md** - This file (quick start and configuration reference)

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review **PRODUCTION.md** for deployment guidance
3. Review the logs with debug level enabled
4. Check the **CODE_REVIEW.md** for implementation details
5. Open an issue with detailed information