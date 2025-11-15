package main

import (
	"errors"
	"fmt"
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
	MaxBodyBytes   int64    `json:"max_body_bytes"`
	AllowedHosts   []string `json:"allowed_hosts"`
	BlockedHosts   []string `json:"blocked_hosts"`
	RequireAuth    bool     `json:"require_auth"`
	AuthUser       string   `json:"auth_user"`
	AuthPassword   string   `json:"auth_password"`
	TLSMinVersion  string   `json:"tls_min_version"`
	EnforceAuthTLS bool     `json:"enforce_auth_tls"`

	// Rate limiting
	EnableRateLimit bool `json:"enable_rate_limit"`
	RateLimitRPS    int  `json:"rate_limit_rps"`
	RateLimitBurst  int  `json:"rate_limit_burst"`

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
		TLSCertFile:   getEnv("PROXY_TLS_CERT_FILE", ""),
		TLSKeyFile:    getEnv("PROXY_TLS_KEY_FILE", ""),
		EnableTLS:     getBoolEnv("PROXY_ENABLE_TLS", false),
		TLSMinVersion: getEnv("PROXY_TLS_MIN_VERSION", "1.2"),

		// Proxy defaults
		EnableHTTPS:         getBoolEnv("PROXY_ENABLE_HTTPS", true),
		ConnectTimeout:      getDurationEnv("PROXY_CONNECT_TIMEOUT", 10*time.Second),
		MaxIdleConns:        getIntEnv("PROXY_MAX_IDLE_CONNS", 100),
		MaxIdleConnsPerHost: getIntEnv("PROXY_MAX_IDLE_CONNS_PER_HOST", 10),

		// Security defaults
		MaxHeaderBytes: getIntEnv("PROXY_MAX_HEADER_BYTES", 1048576),  // 1MB
		MaxBodyBytes:   getInt64Env("PROXY_MAX_BODY_BYTES", 10485760), // 10MB
		AllowedHosts:   getStringSliceEnv("PROXY_ALLOWED_HOSTS", nil),
		BlockedHosts:   getStringSliceEnv("PROXY_BLOCKED_HOSTS", nil),
		RequireAuth:    getBoolEnv("PROXY_REQUIRE_AUTH", false),
		AuthUser:       getEnv("PROXY_AUTH_USER", ""),
		AuthPassword:   getEnv("PROXY_AUTH_PASSWORD", ""),
		EnforceAuthTLS: getBoolEnv("PROXY_ENFORCE_AUTH_TLS", true),

		// Rate limiting defaults
		EnableRateLimit: getBoolEnv("PROXY_ENABLE_RATE_LIMIT", true),
		RateLimitRPS:    getIntEnv("PROXY_RATE_LIMIT_RPS", 100),
		RateLimitBurst:  getIntEnv("PROXY_RATE_LIMIT_BURST", 200),

		// Logging defaults
		LogLevel:  getEnv("PROXY_LOG_LEVEL", "info"),
		LogFormat: getEnv("PROXY_LOG_FORMAT", "json"),
	}

	return config
}

// Validate validates the configuration and returns an error if invalid
func (c *Config) Validate() error {
	var errs []error

	// Validate port
	if c.Port == "" {
		errs = append(errs, errors.New("port cannot be empty"))
	}
	if port, err := strconv.Atoi(c.Port); err != nil || port < 1 || port > 65535 {
		errs = append(errs, fmt.Errorf("invalid port: %s (must be 1-65535)", c.Port))
	}

	// Validate timeouts
	if c.ReadTimeout <= 0 {
		errs = append(errs, errors.New("read_timeout must be positive"))
	}
	if c.WriteTimeout <= 0 {
		errs = append(errs, errors.New("write_timeout must be positive"))
	}
	if c.IdleTimeout <= 0 {
		errs = append(errs, errors.New("idle_timeout must be positive"))
	}
	if c.ConnectTimeout <= 0 {
		errs = append(errs, errors.New("connect_timeout must be positive"))
	}

	// Validate TLS configuration
	if c.EnableTLS {
		if c.TLSCertFile == "" {
			errs = append(errs, errors.New("tls_cert_file required when enable_tls is true"))
		}
		if c.TLSKeyFile == "" {
			errs = append(errs, errors.New("tls_key_file required when enable_tls is true"))
		}
	}

	// Validate authentication
	if c.RequireAuth {
		if c.AuthUser == "" {
			errs = append(errs, errors.New("auth_user required when require_auth is true"))
		}
		if c.AuthPassword == "" {
			errs = append(errs, errors.New("auth_password required when require_auth is true"))
		}
		if len(c.AuthPassword) < 8 {
			errs = append(errs, errors.New("auth_password must be at least 8 characters"))
		}
		// Warn if auth is enabled without TLS
		if c.EnforceAuthTLS && !c.EnableTLS {
			errs = append(errs, errors.New("require_auth enabled without enable_tls: credentials will be sent unencrypted"))
		}
	}

	// Validate connection pool
	if c.MaxIdleConns < 0 {
		errs = append(errs, errors.New("max_idle_conns cannot be negative"))
	}
	if c.MaxIdleConnsPerHost < 0 {
		errs = append(errs, errors.New("max_idle_conns_per_host cannot be negative"))
	}
	if c.MaxIdleConnsPerHost > c.MaxIdleConns {
		errs = append(errs, errors.New("max_idle_conns_per_host cannot exceed max_idle_conns"))
	}

	// Validate limits
	if c.MaxHeaderBytes <= 0 {
		errs = append(errs, errors.New("max_header_bytes must be positive"))
	}
	if c.MaxBodyBytes <= 0 {
		errs = append(errs, errors.New("max_body_bytes must be positive"))
	}

	// Validate rate limiting
	if c.EnableRateLimit {
		if c.RateLimitRPS <= 0 {
			errs = append(errs, errors.New("rate_limit_rps must be positive when enabled"))
		}
		if c.RateLimitBurst <= 0 {
			errs = append(errs, errors.New("rate_limit_burst must be positive when enabled"))
		}
	}

	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "warning", "error"}
	if !contains(validLogLevels, strings.ToLower(c.LogLevel)) {
		errs = append(errs, fmt.Errorf("invalid log_level: %s (must be one of: debug, info, warn, error)", c.LogLevel))
	}

	// Validate log format
	validLogFormats := []string{"json", "text"}
	if !contains(validLogFormats, strings.ToLower(c.LogFormat)) {
		errs = append(errs, fmt.Errorf("invalid log_format: %s (must be json or text)", c.LogFormat))
	}

	if len(errs) > 0 {
		return fmt.Errorf("configuration validation failed: %v", errs)
	}

	return nil
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

func getInt64Env(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}
