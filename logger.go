package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// LogLevel represents different logging levels
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

// Logger provides structured logging functionality
type Logger struct {
	level  LogLevel
	format string
	logger *log.Logger
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Method    string `json:"method,omitempty"`
	URL       string `json:"url,omitempty"`
	Status    int    `json:"status,omitempty"`
	Duration  string `json:"duration,omitempty"`
	RemoteIP  string `json:"remote_ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// NewLogger creates a new logger instance
func NewLogger(config *Config) *Logger {
	level := parseLogLevel(config.LogLevel)
	logger := &Logger{
		level:  level,
		format: config.LogFormat,
		logger: log.New(os.Stdout, "", 0),
	}
	return logger
}

// parseLogLevel converts string log level to LogLevel
func parseLogLevel(level string) LogLevel {
	switch strings.ToLower(level) {
	case "debug":
		return LogLevelDebug
	case "info":
		return LogLevelInfo
	case "warn", "warning":
		return LogLevelWarn
	case "error":
		return LogLevelError
	default:
		return LogLevelInfo
	}
}

// shouldLog checks if message should be logged based on level
func (l *Logger) shouldLog(level LogLevel) bool {
	return level >= l.level
}

// formatLog formats the log entry based on configured format
func (l *Logger) formatLog(entry *LogEntry) string {
	if l.format == "json" {
		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Sprintf("Error marshaling log entry: %v", err)
		}
		return string(data)
	}

	// Text format
	msg := fmt.Sprintf("%s [%s] %s", entry.Timestamp, entry.Level, entry.Message)
	if entry.Method != "" && entry.URL != "" {
		msg += fmt.Sprintf(" - %s %s", entry.Method, entry.URL)
	}
	if entry.Status != 0 {
		msg += fmt.Sprintf(" (Status: %d)", entry.Status)
	}
	if entry.Duration != "" {
		msg += fmt.Sprintf(" (Duration: %s)", entry.Duration)
	}
	if entry.RemoteIP != "" {
		msg += fmt.Sprintf(" (IP: %s)", entry.RemoteIP)
	}
	return msg
}

// log creates and outputs a log entry
func (l *Logger) log(level LogLevel, message string, fields map[string]interface{}) {
	if !l.shouldLog(level) {
		return
	}

	entry := &LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     l.levelToString(level),
		Message:   message,
	}

	// Add optional fields
	if fields != nil {
		if method, ok := fields["method"].(string); ok {
			entry.Method = method
		}
		if url, ok := fields["url"].(string); ok {
			entry.URL = url
		}
		if status, ok := fields["status"].(int); ok {
			entry.Status = status
		}
		if duration, ok := fields["duration"].(time.Duration); ok {
			entry.Duration = duration.String()
		}
		if remoteIP, ok := fields["remote_ip"].(string); ok {
			entry.RemoteIP = remoteIP
		}
		if userAgent, ok := fields["user_agent"].(string); ok {
			entry.UserAgent = userAgent
		}
	}

	l.logger.Println(l.formatLog(entry))
}

// levelToString converts LogLevel to string
func (l *Logger) levelToString(level LogLevel) string {
	switch level {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Debug logs a debug message
func (l *Logger) Debug(message string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LogLevelDebug, message, f)
}

// Info logs an info message
func (l *Logger) Info(message string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LogLevelInfo, message, f)
}

// Warn logs a warning message
func (l *Logger) Warn(message string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LogLevelWarn, message, f)
}

// Error logs an error message
func (l *Logger) Error(message string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LogLevelError, message, f)
}

// LogRequest logs an HTTP request
func (l *Logger) LogRequest(method, url, remoteIP, userAgent string, status int, duration time.Duration) {
	l.Info("HTTP request", map[string]interface{}{
		"method":     method,
		"url":        url,
		"remote_ip":  remoteIP,
		"user_agent": userAgent,
		"status":     status,
		"duration":   duration,
	})
}
