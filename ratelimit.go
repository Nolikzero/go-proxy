package main

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter implements per-IP rate limiting using token bucket algorithm
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
	cleanup  time.Duration
}

// NewRateLimiter creates a new rate limiter
// rps: requests per second per IP
// burst: maximum burst size
func NewRateLimiter(rps int, burst int) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rate.Limit(rps),
		burst:    burst,
		cleanup:  5 * time.Minute,
	}

	// Start cleanup goroutine to remove stale entries
	go rl.cleanupStale()

	return rl
}

// getLimiter returns the rate limiter for the given IP
func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.limiters[ip] = limiter
	}

	return limiter
}

// Allow checks if a request from the given IP should be allowed
func (rl *RateLimiter) Allow(ip string) bool {
	limiter := rl.getLimiter(ip)
	return limiter.Allow()
}

// cleanupStale removes stale rate limiters to prevent memory leaks
func (rl *RateLimiter) cleanupStale() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		// Remove limiters that haven't been used (have full tokens)
		for ip, limiter := range rl.limiters {
			if limiter.Tokens() == float64(rl.burst) {
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
