package main

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter implements per-IP rate limiting using token bucket algorithm
type RateLimiter struct {
	limiters map[string]*limiterEntry
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
	cleanup  time.Duration
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiter
// rps: requests per second per IP
// burst: maximum burst size
func NewRateLimiter(rps int, burst int) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*limiterEntry),
		rate:     rate.Limit(rps),
		burst:    burst,
		cleanup:  5 * time.Minute,
	}

	// Start cleanup goroutine to remove stale entries
	go rl.cleanupStale()

	return rl
}

// getLimiter returns the rate limiter for the given IP
func (rl *RateLimiter) getLimiter(ip string) *limiterEntry {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.limiters[ip]
	if !exists {
		entry = &limiterEntry{
			limiter:  rate.NewLimiter(rl.rate, rl.burst),
			lastSeen: time.Now(),
		}
		rl.limiters[ip] = entry
	} else {
		entry.lastSeen = time.Now()
	}

	return entry
}

// Allow checks if a request from the given IP should be allowed
func (rl *RateLimiter) Allow(ip string) bool {
	entry := rl.getLimiter(ip)
	return entry.limiter.Allow()
}

// cleanupStale removes stale rate limiters to prevent memory leaks
func (rl *RateLimiter) cleanupStale() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		threshold := time.Now().Add(-rl.cleanup)
		for ip, entry := range rl.limiters {
			if entry.lastSeen.Before(threshold) {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Middleware returns a rate limiting middleware
func (rl *RateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		if !rl.Allow(ip) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	}
}
