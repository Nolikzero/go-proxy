package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the proxy server
type Config struct {
	// Server configuration
	Port         string        `json:"port"`
	Host         string        `json:"host"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`

	// TLS configuration
	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`
	EnableTLS   bool   `json:"enable_tls"`

	// Proxy configuration
	EnableHTTPS         bool          `json:"enable_https"`
	ConnectTimeout      time.Duration `json:"connect_timeout"`
	MaxIdleConns        int           `json:"max_idle_conns"`
	MaxIdleConnsPerHost int           `json:"max_idle_conns_per_host"`

	// Security and limits
	MaxHeaderBytes int      `json:"max_header_bytes"`
	AllowedHosts   []string `json:"allowed_hosts"`
	BlockedHosts   []string `json:"blocked_hosts"`
	RequireAuth    bool     `json:"require_auth"`
	AuthUser       string   `json:"auth_user"`
	AuthPassword   string   `json:"auth_password"`

	// Logging
	LogLevel  string `json:"log_level"`
	LogFormat string `json:"log_format"`
}

// LoadConfig loads configuration from environment variables with sensible defaults
func LoadConfig() *Config {
	config := &Config{
		// Server defaults
		Port:         getEnv("PROXY_PORT", "8080"),
		Host:         getEnv("PROXY_HOST", ""),
		ReadTimeout:  getDurationEnv("PROXY_READ_TIMEOUT", 30*time.Second),
		WriteTimeout: getDurationEnv("PROXY_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:  getDurationEnv("PROXY_IDLE_TIMEOUT", 120*time.Second),

		// TLS defaults
		TLSCertFile: getEnv("PROXY_TLS_CERT_FILE", ""),
		TLSKeyFile:  getEnv("PROXY_TLS_KEY_FILE", ""),
		EnableTLS:   getBoolEnv("PROXY_ENABLE_TLS", false),

		// Proxy defaults
		EnableHTTPS:         getBoolEnv("PROXY_ENABLE_HTTPS", true),
		ConnectTimeout:      getDurationEnv("PROXY_CONNECT_TIMEOUT", 10*time.Second),
		MaxIdleConns:        getIntEnv("PROXY_MAX_IDLE_CONNS", 100),
		MaxIdleConnsPerHost: getIntEnv("PROXY_MAX_IDLE_CONNS_PER_HOST", 10),

		// Security defaults
		MaxHeaderBytes: getIntEnv("PROXY_MAX_HEADER_BYTES", 1048576), // 1MB
		AllowedHosts:   getStringSliceEnv("PROXY_ALLOWED_HOSTS", nil),
		BlockedHosts:   getStringSliceEnv("PROXY_BLOCKED_HOSTS", nil),
		RequireAuth:    getBoolEnv("PROXY_REQUIRE_AUTH", false),
		AuthUser:       getEnv("PROXY_AUTH_USER", ""),
		AuthPassword:   getEnv("PROXY_AUTH_PASSWORD", ""),

		// Logging defaults
		LogLevel:  getEnv("PROXY_LOG_LEVEL", "info"),
		LogFormat: getEnv("PROXY_LOG_FORMAT", "json"),
	}

	return config
}

// Helper functions for environment variable parsing
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getStringSliceEnv(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}
