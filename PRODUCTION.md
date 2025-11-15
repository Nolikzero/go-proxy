# Production Deployment Guide

## Overview
This guide provides comprehensive instructions for deploying the Go HTTP/HTTPS proxy in a production environment with security, performance, and operational best practices.

## Table of Contents
1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Security Configuration](#security-configuration)
3. [Performance Tuning](#performance-tuning)
4. [Monitoring and Observability](#monitoring-and-observability)
5. [High Availability Setup](#high-availability-setup)
6. [Operational Procedures](#operational-procedures)
7. [Troubleshooting](#troubleshooting)

---

## Pre-Deployment Checklist

### ✅ Configuration Validation
- [ ] Review and set all required environment variables
- [ ] Test configuration validation with `go run . --validate-config`
- [ ] Ensure TLS certificates are valid and not expired
- [ ] Verify authentication credentials are strong (minimum 12 characters)
- [ ] Set appropriate rate limits based on expected traffic

### ✅ Security Review
- [ ] Enable TLS for the proxy server (`PROXY_ENABLE_TLS=true`)
- [ ] Enable authentication (`PROXY_REQUIRE_AUTH=true`)
- [ ] Configure firewall rules to restrict access
- [ ] Set `PROXY_ENFORCE_AUTH_TLS=true` to prevent unencrypted auth
- [ ] Review and configure allowed/blocked hosts
- [ ] Ensure running as non-root user

### ✅ Resource Planning
- [ ] Calculate expected QPS (queries per second)
- [ ] Determine appropriate connection pool sizes
- [ ] Plan for horizontal scaling if needed
- [ ] Set up monitoring and alerting
- [ ] Configure log aggregation

---

## Security Configuration

### TLS/SSL Setup

#### Generate Self-Signed Certificate (Development Only)
```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \\
    -days 365 -nodes -subj "/CN=proxy.example.com"
```

#### Production TLS Certificate
Use Let's Encrypt or your organization's CA:
```bash
# Using certbot for Let's Encrypt
certbot certonly --standalone -d proxy.example.com
```

#### Configure TLS Environment Variables
```bash
export PROXY_ENABLE_TLS=true
export PROXY_TLS_CERT_FILE=/path/to/server.crt
export PROXY_TLS_KEY_FILE=/path/to/server.key
export PROXY_TLS_MIN_VERSION=1.3  # Use TLS 1.3 for best security
```

### Authentication Configuration

```bash
export PROXY_REQUIRE_AUTH=true
export PROXY_AUTH_USER=admin
export PROXY_AUTH_PASSWORD=$(openssl rand -base64 24)  # Generate strong password
export PROXY_ENFORCE_AUTH_TLS=true  # Enforce TLS when auth is enabled
```

**⚠️ CRITICAL:** Never use basic authentication without TLS in production!

### Host Filtering

```bash
# Allow only specific domains (whitelist approach - most secure)
export PROXY_ALLOWED_HOSTS="api.example.com,cdn.example.com,metrics.example.com"

# Or block specific domains (blacklist approach)
export PROXY_BLOCKED_HOSTS="malicious.com,spam.com"
```

### Rate Limiting

```bash
export PROXY_ENABLE_RATE_LIMIT=true
export PROXY_RATE_LIMIT_RPS=100      # Requests per second per IP
export PROXY_RATE_LIMIT_BURST=200    # Burst capacity
```

**Recommended Rate Limits by Use Case:**
- Internal API proxy: 1000 RPS, 2000 burst
- Public proxy: 100 RPS, 200 burst
- Development proxy: 50 RPS, 100 burst

---

## Performance Tuning

### Connection Pool Configuration

```bash
# Optimize for high throughput
export PROXY_MAX_IDLE_CONNS=500
export PROXY_MAX_IDLE_CONNS_PER_HOST=50

# Optimize for many unique hosts
export PROXY_MAX_IDLE_CONNS=1000
export PROXY_MAX_IDLE_CONNS_PER_HOST=10
```

### Timeout Configuration

```bash
# Aggressive timeouts (for fast APIs)
export PROXY_READ_TIMEOUT=10s
export PROXY_WRITE_TIMEOUT=10s
export PROXY_CONNECT_TIMEOUT=5s
export PROXY_IDLE_TIMEOUT=60s
export PROXY_TUNNEL_IDLE_TIMEOUT=2m
export PROXY_TUNNEL_KEEP_ALIVE_INTERVAL=30s

# Relaxed timeouts (for slow APIs/large transfers)
export PROXY_READ_TIMEOUT=60s
export PROXY_WRITE_TIMEOUT=60s
export PROXY_CONNECT_TIMEOUT=15s
export PROXY_IDLE_TIMEOUT=180s
export PROXY_TUNNEL_IDLE_TIMEOUT=30m
export PROXY_TUNNEL_KEEP_ALIVE_INTERVAL=1m
```

#### Long-Lived AI / Streaming Sessions

```bash
export PROXY_TUNNEL_IDLE_TIMEOUT=4h   # Keep CONNECT tunnels alive while traffic is flowing
export PROXY_TUNNEL_KEEP_ALIVE_INTERVAL=15s
export PROXY_MAX_IDLE_CONNS=500
export PROXY_MAX_IDLE_CONNS_PER_HOST=50
```

> ℹ️ The regular HTTP server timeouts stay protective, while tunnel-specific settings make sure hijacked TCP streams remain healthy for multi-minute or multi-hour conversations.

### Request/Response Size Limits

```bash
export PROXY_MAX_HEADER_BYTES=1048576   # 1 MB
export PROXY_MAX_BODY_BYTES=104857600   # 100 MB (adjust based on use case)
```

### System Tuning (Linux)

#### Increase File Descriptor Limits
```bash
# /etc/security/limits.conf
* soft nofile 65536
* hard nofile 65536
```

#### TCP Stack Tuning
```bash
# /etc/sysctl.conf
net.core.somaxconn=4096
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=30
```

Apply changes:
```bash
sysctl -p
```

---

## Monitoring and Observability

### Prometheus Metrics

The proxy exposes metrics at `http://proxy-host:port/metrics`

#### Key Metrics to Monitor

**Request Metrics:**
- `proxy_requests_total` - Total requests (by method and status)
- `proxy_request_duration_seconds` - Request latency histogram
- `proxy_requests_in_flight` - Current concurrent requests

**Resource Metrics:**
- `proxy_tunnels_active` - Active HTTPS tunnels
- `proxy_bytes_transferred_total` - Data transfer (inbound/outbound)

**Error Metrics:**
- `proxy_upstream_errors_total` - Upstream connection failures
- `proxy_rate_limit_exceeded_total` - Rate limit violations per IP
- `proxy_auth_failures_total` - Authentication failures
- `proxy_host_blocked_total` - Blocked host attempts

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'go-proxy'
    static_configs:
      - targets: ['proxy:8080']
    scrape_interval: 15s
    metrics_path: /metrics
```

### Grafana Dashboard

Import the included `grafana-dashboard.json` or create custom panels for:
- Request rate and latency (P50, P95, P99)
- Error rates by type
- Active connections and tunnels
- Rate limit violations
- Resource utilization

### Alerting Rules

```yaml
# alerting-rules.yml
groups:
  - name: proxy_alerts
    rules:
      - alert: ProxyHighErrorRate
        expr: rate(proxy_upstream_errors_total[5m]) > 10
        for: 5m
        annotations:
          summary: "High error rate on proxy"
          
      - alert: ProxyHighLatency
        expr: histogram_quantile(0.95, proxy_request_duration_seconds) > 5
        for: 5m
        annotations:
          summary: "95th percentile latency above 5s"
          
      - alert: ProxyRateLimitExceeded
        expr: rate(proxy_rate_limit_exceeded_total[1m]) > 100
        for: 2m
        annotations:
          summary: "High rate of rate limit violations"
```

### Health Checks

**Kubernetes Liveness Probe:**
```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 10
```

**Kubernetes Readiness Probe:**
```yaml
readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

---

## High Availability Setup

### Docker Swarm Deployment

```yaml
# docker-compose-ha.yml
version: '3.8'

services:
  go-proxy:
    image: go-proxy:latest
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
        max_attempts: 3
    ports:
      - "8080:8080"
    environment:
      - PROXY_ENABLE_RATE_LIMIT=true
      - PROXY_RATE_LIMIT_RPS=100
    networks:
      - proxy-net
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:8080/healthz"]
      interval: 30s
      timeout: 3s
      retries: 3

  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    networks:
      - proxy-net

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    networks:
      - proxy-net

networks:
  proxy-net:
    driver: overlay
```

Deploy:
```bash
docker stack deploy -c docker-compose-ha.yml proxy-stack
```

### Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: go-proxy
  labels:
    app: go-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: go-proxy
  template:
    metadata:
      labels:
        app: go-proxy
    spec:
      containers:
      - name: go-proxy
        image: go-proxy:latest
        ports:
        - containerPort: 8080
        env:
        - name: PROXY_PORT
          value: "8080"
        - name: PROXY_ENABLE_RATE_LIMIT
          value: "true"
        - name: PROXY_RATE_LIMIT_RPS
          value: "100"
        - name: PROXY_ENABLE_TLS
          valueFrom:
            configMapKeyRef:
              name: proxy-config
              key: enable-tls
        - name: PROXY_AUTH_USER
          valueFrom:
            secretKeyRef:
              name: proxy-secrets
              key: auth-user
        - name: PROXY_AUTH_PASSWORD
          valueFrom:
            secretKeyRef:
              name: proxy-secrets
              key: auth-password
        resources:
          requests:
            memory: "128Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        fsGroup: 65534
---
apiVersion: v1
kind: Service
metadata:
  name: go-proxy-service
spec:
  selector:
    app: go-proxy
  ports:
  - protocol: TCP
    port: 8080
    targetPort: 8080
  type: LoadBalancer
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: go-proxy-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: go-proxy
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Load Balancer Configuration

#### NGINX Upstream
```nginx
upstream go_proxy {
    least_conn;
    server proxy1:8080 max_fails=3 fail_timeout=30s;
    server proxy2:8080 max_fails=3 fail_timeout=30s;
    server proxy3:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name proxy.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://go_proxy;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

---

## Operational Procedures

### Deployment

1. **Build and test:**
   ```bash
   make build
   make test
   go run . --validate-config
   ```

2. **Build Docker image:**
   ```bash
   docker build -t go-proxy:v1.0.0 .
   docker tag go-proxy:v1.0.0 registry.example.com/go-proxy:v1.0.0
   docker push registry.example.com/go-proxy:v1.0.0
   ```

3. **Rolling deployment (zero downtime):**
   ```bash
   kubectl set image deployment/go-proxy go-proxy=go-proxy:v1.0.0 --record
   kubectl rollout status deployment/go-proxy
   ```

### Backup and Recovery

**Configuration Backup:**
```bash
# Backup environment configuration
kubectl get configmap proxy-config -o yaml > proxy-config-backup.yaml
kubectl get secret proxy-secrets -o yaml > proxy-secrets-backup.yaml
```

**Restore:**
```bash
kubectl apply -f proxy-config-backup.yaml
kubectl apply -f proxy-secrets-backup.yaml
kubectl rollout restart deployment/go-proxy
```

### Scaling

**Vertical Scaling (increase resources):**
```bash
kubectl set resources deployment go-proxy \\
    --limits=cpu=2000m,memory=1Gi \\
    --requests=cpu=500m,memory=256Mi
```

**Horizontal Scaling (add instances):**
```bash
kubectl scale deployment go-proxy --replicas=5
```

### Log Management

**Centralized Logging (Fluent Bit example):**
```yaml
# fluent-bit-config.yaml
[INPUT]
    Name tail
    Path /var/log/containers/*go-proxy*.log
    Parser json

[FILTER]
    Name kubernetes
    Match *

[OUTPUT]
    Name es
    Match *
    Host elasticsearch
    Port 9200
```

---

## Troubleshooting

### Common Issues

#### 1. High Memory Usage
**Symptoms:** Container OOM kills, high memory metrics

**Solutions:**
- Reduce `PROXY_MAX_IDLE_CONNS`
- Lower `PROXY_MAX_BODY_BYTES`
- Check for memory leaks with pprof
- Increase container memory limits

#### 2. Connection Timeouts
**Symptoms:** 504 Gateway Timeout errors

**Solutions:**
- Increase `PROXY_CONNECT_TIMEOUT`
- Check upstream service health
- Verify network connectivity
- Review firewall rules

#### 3. Rate Limit Violations
**Symptoms:** Many 429 responses, `proxy_rate_limit_exceeded_total` increasing

**Solutions:**
- Identify abusive IPs: `kubectl logs deployment/go-proxy | grep "Rate limit exceeded"`
- Increase rate limits if legitimate traffic
- Implement IP-based blocking
- Add WAF protection

#### 4. TLS Handshake Failures
**Symptoms:** TLS handshake timeout, certificate errors

**Solutions:**
- Verify certificate validity: `openssl x509 -in cert.pem -text -noout`
- Check certificate chain
- Ensure correct `PROXY_TLS_MIN_VERSION`
- Verify system time is synchronized

### Debug Mode

Enable debug logging:
```bash
export PROXY_LOG_LEVEL=debug
```

### Performance Profiling

Enable pprof (add to main.go for debugging):
```go
import _ "net/http/pprof"

// In main():
go func() {
    log.Println(http.ListenAndServe("localhost:6060", nil))
}()
```

Profile CPU:
```bash
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
```

Profile Memory:
```bash
go tool pprof http://localhost:6060/debug/pprof/heap
```

---

## Security Best Practices Summary

1. ✅ **Always use TLS in production**
2. ✅ **Enable authentication with strong passwords**
3. ✅ **Run as non-root user**
4. ✅ **Use host filtering (whitelist preferred)**
5. ✅ **Enable rate limiting**
6. ✅ **Keep dependencies updated**
7. ✅ **Monitor and alert on security events**
8. ✅ **Regular security audits**
9. ✅ **Implement network segmentation**
10. ✅ **Use secrets management (not env vars in prod)**

---

## Performance Benchmarks

Expected performance on standard hardware (4 CPU cores, 8GB RAM):

- **HTTP Requests:** ~10,000 RPS
- **HTTPS Tunnels:** ~5,000 concurrent connections
- **Latency (P95):** < 50ms (without upstream)
- **Memory per instance:** ~200-500 MB
- **CPU per instance:** 1-2 cores under load

Benchmark your specific deployment:
```bash
# Using Apache Bench
ab -n 10000 -c 100 -X localhost:8080 http://example.com/

# Using hey
hey -n 10000 -c 100 -x http://localhost:8080 http://example.com/
```

---

## Support and Maintenance

**Regular Maintenance Tasks:**
- Weekly: Review logs and metrics
- Monthly: Security updates, certificate rotation
- Quarterly: Performance review, capacity planning
- Annually: Full security audit

**Useful Commands:**
```bash
# Check proxy health
curl http://localhost:8080/healthz

# View metrics
curl http://localhost:8080/metrics

# Test proxy
curl -x http://localhost:8080 http://example.com

# Test with authentication
curl -x http://user:pass@localhost:8080 https://example.com
```

---

## Additional Resources

- [Go HTTP Package Documentation](https://pkg.go.dev/net/http)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/)
- [Kubernetes Production Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [OWASP API Security](https://owasp.org/www-project-api-security/)
