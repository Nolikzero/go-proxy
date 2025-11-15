package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"
)

// ProxyServer represents the HTTP/HTTPS proxy server
type ProxyServer struct {
	config      *Config
	logger      *Logger
	server      *http.Server
	client      *http.Client
	metrics     *Metrics
	rateLimiter *RateLimiter
}

// NewProxyServer creates a new proxy server instance
func NewProxyServer(config *Config, logger *Logger, metrics *Metrics) *ProxyServer {
	// Create HTTP client with optimized settings for proxy usage
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   config.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// Enable HTTP/2
		ForceAttemptHTTP2: true,
	}

	// Configure TLS for HTTPS proxy with secure defaults
	if config.EnableHTTPS {
		minVersion := tls.VersionTLS12
		if config.TLSMinVersion == "1.3" {
			minVersion = tls.VersionTLS13
		}
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         uint16(minVersion),
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.ConnectTimeout + config.ReadTimeout,
	}

	// Initialize rate limiter if enabled
	var rateLimiter *RateLimiter
	if config.EnableRateLimit {
		rateLimiter = NewRateLimiter(config.RateLimitRPS, config.RateLimitBurst)
	}

	return &ProxyServer{
		config:      config,
		logger:      logger,
		client:      client,
		metrics:     metrics,
		rateLimiter: rateLimiter,
	}
}

// Start starts the proxy server
func (p *ProxyServer) Start() error {
	// Build middleware chain
	proxyChain := p.loggingMiddleware(
		p.metricsMiddleware(
			p.rateLimitMiddleware(
				p.authMiddleware(
					p.hostFilterMiddleware(
						p.proxyHandler(),
					),
				),
			),
		),
	)

	healthHandler := p.healthHandler()
	metricsHandler := p.metrics.Handler()

	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve special endpoints without proxy middleware
		if r.Method != http.MethodConnect {
			if r.URL != nil {
				path := r.URL.Path
				if path == "/healthz" || path == "/health" {
					healthHandler(w, r)
					return
				}
				if path == "/metrics" {
					metricsHandler.ServeHTTP(w, r)
					return
				}
			}
		}

		proxyChain(w, r)
	})

	// Configure server
	addr := net.JoinHostPort(p.config.Host, p.config.Port)
	p.server = &http.Server{
		Addr:           addr,
		Handler:        rootHandler,
		ReadTimeout:    p.config.ReadTimeout,
		WriteTimeout:   p.config.WriteTimeout,
		IdleTimeout:    p.config.IdleTimeout,
		MaxHeaderBytes: p.config.MaxHeaderBytes,
	}

	p.logger.Info("Starting proxy server", map[string]interface{}{
		"address":      addr,
		"tls_enabled":  p.config.EnableTLS,
		"rate_limit":   p.config.EnableRateLimit,
		"auth_enabled": p.config.RequireAuth,
	})

	// Start server with or without TLS
	if p.config.EnableTLS && p.config.TLSCertFile != "" && p.config.TLSKeyFile != "" {
		return p.server.ListenAndServeTLS(p.config.TLSCertFile, p.config.TLSKeyFile)
	}

	return p.server.ListenAndServe()
}

// Stop gracefully stops the proxy server
func (p *ProxyServer) Stop(ctx context.Context) error {
	p.logger.Info("Shutting down proxy server")
	return p.server.Shutdown(ctx)
}

// proxyHandler returns the main proxy handler function
func (p *ProxyServer) proxyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Handle CONNECT method for HTTPS tunneling
		if r.Method == http.MethodConnect {
			p.handleTunnel(w, r)
			return
		}

		// Handle regular HTTP requests
		p.handleHTTP(w, r)
	}
}

// handleHTTP handles regular HTTP proxy requests
func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Limit request body size
	if p.config.MaxBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, p.config.MaxBodyBytes)
	}

	// Create new request with the same parameters
	targetURL := r.URL
	if !targetURL.IsAbs() {
		http.Error(w, "Request must be absolute URL", http.StatusBadRequest)
		return
	}

	// Create new request with context that respects parent cancellation
	ctx := r.Context()
	proxyReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL.String(), r.Body)
	if err != nil {
		p.logger.Error("Failed to create proxy request", map[string]interface{}{
			"error": err.Error(),
			"url":   targetURL.String(),
		})
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	p.copyHeaders(proxyReq.Header, r.Header)

	// Remove hop-by-hop headers
	p.removeHopByHopHeaders(proxyReq.Header)

	// Add X-Forwarded headers
	p.addForwardedHeaders(proxyReq, r)

	// Execute the request
	start := time.Now()
	resp, err := p.client.Do(proxyReq)
	duration := time.Since(start)

	if err != nil {
		p.logger.Error("Proxy request failed", map[string]interface{}{
			"error":    err.Error(),
			"url":      targetURL.String(),
			"duration": duration,
		})

		// Classify error type for metrics
		errorType := "other"
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			errorType = "timeout"
		}
		p.metrics.RecordUpstreamError(errorType)

		http.Error(w, "Proxy request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	p.copyHeaders(w.Header(), resp.Header)
	p.removeHopByHopHeaders(w.Header())

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body with size tracking
	written, err := io.Copy(w, resp.Body)
	if err != nil {
		p.logger.Error("Failed to copy response body", map[string]interface{}{
			"error": err.Error(),
		})
	}

	if written > 0 {
		p.metrics.RecordBytesTransferred("outbound", written)
	}

	p.logger.LogRequest(r.Method, targetURL.String(), getClientIP(r), r.UserAgent(), resp.StatusCode, duration)
}

// handleTunnel handles CONNECT method for HTTPS tunneling
func (p *ProxyServer) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if !p.config.EnableHTTPS {
		http.Error(w, "HTTPS tunneling disabled", http.StatusMethodNotAllowed)
		return
	}

	// Track tunnel
	p.metrics.IncrementTunnels()
	defer p.metrics.DecrementTunnels()

	// Connect to the target server with timeout
	targetConn, err := net.DialTimeout("tcp", r.Host, p.config.ConnectTimeout)
	if err != nil {
		p.logger.Error("Failed to connect to target", map[string]interface{}{
			"error": err.Error(),
			"host":  r.Host,
		})
		p.metrics.RecordUpstreamError("connect")
		http.Error(w, "Failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Set deadlines for connection
	deadline := time.Now().Add(p.config.WriteTimeout)
	targetConn.SetDeadline(deadline)

	// Hijack the connection so we can proxy raw TCP
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buf, err := hj.Hijack()
	if err != nil {
		p.logger.Error("Failed to hijack connection", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
	defer clientConn.Close()

	// Set deadline for client connection
	clientConn.SetDeadline(deadline)

	if buf == nil {
		buf = bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn))
	}

	// Respond to client that tunnel is established
	if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\\r\\n\\r\\n"); err != nil {
		p.logger.Error("Failed to write tunnel response", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
	if err := buf.Flush(); err != nil {
		p.logger.Error("Failed to flush tunnel response", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	start := time.Now()

	// Start bidirectional copying with error handling
	errChan := make(chan error, 2)
	var bytesClientToTarget, bytesTargetToClient int64

	// Client to target
	go func() {
		n, err := io.Copy(targetConn, clientConn)
		bytesClientToTarget = n
		errChan <- err
	}()

	// Target to client
	go func() {
		n, err := io.Copy(clientConn, targetConn)
		bytesTargetToClient = n
		errChan <- err
	}()

	// Wait for first direction to complete
	err = <-errChan
	if err != nil && err != io.EOF {
		p.logger.Debug("Tunnel copy error", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Close connections to force the other direction to finish
	clientConn.Close()
	targetConn.Close()

	// Wait for second direction
	<-errChan

	duration := time.Since(start)

	// Record bytes transferred
	if bytesClientToTarget > 0 {
		p.metrics.RecordBytesTransferred("inbound", bytesClientToTarget)
	}
	if bytesTargetToClient > 0 {
		p.metrics.RecordBytesTransferred("outbound", bytesTargetToClient)
	}

	p.logger.LogRequest(r.Method, r.Host, getClientIP(r), r.UserAgent(), http.StatusOK, duration)
}

// loggingMiddleware logs HTTP requests
func (p *ProxyServer) loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create response writer wrapper to capture status code
		wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapper, r)

		duration := time.Since(start)

		// Log the request (if not already logged in handlers)
		if r.Method != http.MethodConnect {
			p.logger.LogRequest(r.Method, r.URL.String(), getClientIP(r), r.UserAgent(), wrapper.statusCode, duration)
		}
	}
}

// metricsMiddleware tracks request metrics
func (p *ProxyServer) metricsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.metrics.IncrementInFlight()
		defer p.metrics.DecrementInFlight()

		start := time.Now()
		wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapper, r)

		duration := time.Since(start).Seconds()
		p.metrics.RecordRequest(r.Method, wrapper.statusCode, duration)
	}
}

// rateLimitMiddleware applies rate limiting if enabled
func (p *ProxyServer) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.config.EnableRateLimit && p.rateLimiter != nil {
			ip := getClientIP(r)
			if !p.rateLimiter.Allow(ip) {
				p.metrics.RecordRateLimitExceeded(ip)
				p.logger.Warn("Rate limit exceeded", map[string]interface{}{
					"remote_ip": ip,
				})
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	}
}

// authMiddleware handles basic authentication if enabled
func (p *ProxyServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.config.RequireAuth {
			next.ServeHTTP(w, r)
			return
		}

		// Check for Proxy-Authorization header
		auth := r.Header.Get("Proxy-Authorization")
		if auth == "" {
			p.metrics.RecordAuthFailure()
			w.Header().Set("Proxy-Authenticate", "Basic realm=\\\"Proxy\\\"")
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
			return
		}

		// Parse Basic auth
		if !strings.HasPrefix(auth, "Basic ") {
			p.metrics.RecordAuthFailure()
			http.Error(w, "Invalid authentication method", http.StatusProxyAuthRequired)
			return
		}

		encoded := auth[6:]
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			p.metrics.RecordAuthFailure()
			http.Error(w, "Invalid authentication", http.StatusProxyAuthRequired)
			return
		}

		credentials := strings.SplitN(string(decoded), ":", 2)
		if len(credentials) != 2 || credentials[0] != p.config.AuthUser || credentials[1] != p.config.AuthPassword {
			p.metrics.RecordAuthFailure()
			http.Error(w, "Invalid credentials", http.StatusProxyAuthRequired)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// hostFilterMiddleware filters requests based on allowed/blocked hosts
func (p *ProxyServer) hostFilterMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var host string

		if r.Method == http.MethodConnect {
			host = r.Host
		} else if r.URL != nil {
			parsed, err := url.Parse(r.URL.String())
			if err == nil {
				host = parsed.Host
			}
		}

		// Remove port from host for comparison
		if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
			host = host[:colonIndex]
		}

		// Check blocked hosts
		if len(p.config.BlockedHosts) > 0 && slices.Contains(p.config.BlockedHosts, host) {
			p.metrics.RecordHostBlocked()
			p.logger.Warn("Blocked host access attempt", map[string]interface{}{
				"host":      host,
				"remote_ip": getClientIP(r),
			})
			http.Error(w, "Access to this host is blocked", http.StatusForbidden)
			return
		}

		// Check allowed hosts (if configured)
		if len(p.config.AllowedHosts) > 0 && !slices.Contains(p.config.AllowedHosts, host) {
			p.metrics.RecordHostBlocked()
			p.logger.Warn("Unauthorized host access attempt", map[string]interface{}{
				"host":      host,
				"remote_ip": getClientIP(r),
			})
			http.Error(w, "Access to this host is not allowed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// healthHandler provides a lightweight readiness/liveness response
func (p *ProxyServer) healthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			}
		default:
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// Helper functions

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("response writer does not support hijacking")
}

// copyHeaders copies HTTP headers from source to destination
func (p *ProxyServer) copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// removeHopByHopHeaders removes hop-by-hop headers that shouldn't be forwarded
func (p *ProxyServer) removeHopByHopHeaders(header http.Header) {
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

// addForwardedHeaders adds X-Forwarded headers
func (p *ProxyServer) addForwardedHeaders(proxyReq, originalReq *http.Request) {
	clientIP := getClientIP(originalReq)
	proxyReq.Header.Set("X-Forwarded-For", clientIP)
	proxyReq.Header.Set("X-Forwarded-Proto", getScheme(originalReq))

	if originalReq.Host != "" {
		proxyReq.Header.Set("X-Forwarded-Host", originalReq.Host)
	}
}

// getClientIP extracts the real client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Get first IP from comma-separated list
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// getScheme determines the request scheme
func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}

	forwarded := r.Header.Get("X-Forwarded-Proto")
	if forwarded != "" {
		return forwarded
	}

	return "http"
}

// main function
func main() {
	// Load configuration
	config := LoadConfig()

	// Validate configuration
	if err := config.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration validation failed: %v\\n", err)
		os.Exit(1)
	}

	// Create logger
	logger := NewLogger(config)

	logger.Info("Starting proxy server", map[string]interface{}{
		"version": "1.0.0",
		"config":  "validated",
	})

	// Initialize metrics
	metrics := NewMetrics()

	// Create proxy server
	proxy := NewProxyServer(config, logger, metrics)

	// Setup graceful shutdown
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal")
		cancel()

		// Give 30 seconds for graceful shutdown
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := proxy.Stop(shutdownCtx); err != nil {
			logger.Error("Error during shutdown", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}()

	// Start server
	err := proxy.Start()
	if err != nil && err != http.ErrServerClosed {
		logger.Error("Server failed to start", map[string]interface{}{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	logger.Info("Proxy server stopped")
}
