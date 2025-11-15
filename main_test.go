package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestConfigValidation tests the configuration validation
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Port:                "8080",
				ReadTimeout:         30 * time.Second,
				WriteTimeout:        30 * time.Second,
				IdleTimeout:         120 * time.Second,
				ConnectTimeout:      10 * time.Second,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				MaxHeaderBytes:      1048576,
				MaxBodyBytes:        10485760,
				LogLevel:            "info",
				LogFormat:           "json",
				EnableRateLimit:     true,
				RateLimitRPS:        100,
				RateLimitBurst:      200,
			},
			wantErr: false,
		},
		{
			name: "invalid port",
			config: &Config{
				Port:                "99999",
				ReadTimeout:         30 * time.Second,
				WriteTimeout:        30 * time.Second,
				IdleTimeout:         120 * time.Second,
				ConnectTimeout:      10 * time.Second,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				MaxHeaderBytes:      1048576,
				MaxBodyBytes:        10485760,
				LogLevel:            "info",
				LogFormat:           "json",
			},
			wantErr: true,
		},
		{
			name: "auth without credentials",
			config: &Config{
				Port:                "8080",
				ReadTimeout:         30 * time.Second,
				WriteTimeout:        30 * time.Second,
				IdleTimeout:         120 * time.Second,
				ConnectTimeout:      10 * time.Second,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				MaxHeaderBytes:      1048576,
				MaxBodyBytes:        10485760,
				RequireAuth:         true,
				LogLevel:            "info",
				LogFormat:           "json",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRateLimiter tests the rate limiting functionality
func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(2, 2) // 2 requests per second, burst of 2

	// First two requests should pass
	if !rl.Allow("192.168.1.1") {
		t.Error("First request should be allowed")
	}
	if !rl.Allow("192.168.1.1") {
		t.Error("Second request should be allowed")
	}

	// Third request should fail (rate limit exceeded)
	if rl.Allow("192.168.1.1") {
		t.Error("Third request should be rate limited")
	}

	// Different IP should be allowed
	if !rl.Allow("192.168.1.2") {
		t.Error("Request from different IP should be allowed")
	}
}

// TestHealthHandler tests the health check endpoint
func TestHealthHandler(t *testing.T) {
	config := &Config{
		Port:                "8080",
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		IdleTimeout:         120 * time.Second,
		ConnectTimeout:      10 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxHeaderBytes:      1048576,
		MaxBodyBytes:        10485760,
		LogLevel:            "info",
		LogFormat:           "json",
	}

	logger := NewLogger(config)
	metrics := NewMetrics()
	proxy := NewProxyServer(config, logger, metrics)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	proxy.healthHandler()(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", w.Code)
	}

	if w.Body.String() != `{"status":"ok"}` {
		t.Errorf("Expected {\"status\":\"ok\"}, got %s", w.Body.String())
	}
}

// TestAuthMiddleware tests the authentication middleware
func TestAuthMiddleware(t *testing.T) {
	config := &Config{
		Port:                "8080",
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		IdleTimeout:         120 * time.Second,
		ConnectTimeout:      10 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxHeaderBytes:      1048576,
		MaxBodyBytes:        10485760,
		RequireAuth:         true,
		AuthUser:            "testuser",
		AuthPassword:        "testpass123",
		LogLevel:            "info",
		LogFormat:           "json",
	}

	logger := NewLogger(config)
	metrics := NewMetrics()
	proxy := NewProxyServer(config, logger, metrics)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := proxy.authMiddleware(nextHandler)

	// Test without auth header
	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()
	middleware(w, req)

	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("Expected status 407, got %d", w.Code)
	}

	// Test with valid auth
	req = httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Proxy-Authorization", "Basic dGVzdHVzZXI6dGVzdHBhc3MxMjM=") // base64(testuser:testpass123)
	w = httptest.NewRecorder()
	middleware(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestGracefulShutdown tests graceful shutdown
func TestGracefulShutdown(t *testing.T) {
	config := &Config{
		Port:                "18080",
		Host:                "127.0.0.1",
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		IdleTimeout:         120 * time.Second,
		ConnectTimeout:      10 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxHeaderBytes:      1048576,
		MaxBodyBytes:        10485760,
		LogLevel:            "info",
		LogFormat:           "json",
	}

	logger := NewLogger(config)
	metrics := NewMetrics()
	proxy := NewProxyServer(config, logger, metrics)

	// Start server in goroutine
	go func() {
		_ = proxy.Start()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := proxy.Stop(ctx)
	if err != nil {
		t.Errorf("Graceful shutdown failed: %v", err)
	}
}
