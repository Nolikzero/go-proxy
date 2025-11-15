package main

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricsOnce   sync.Once
	globalMetrics *Metrics
)

// Metrics holds all Prometheus metrics
type Metrics struct {
	requestsTotal     *prometheus.CounterVec
	requestDuration   *prometheus.HistogramVec
	requestsInFlight  prometheus.Gauge
	tunnelsActive     prometheus.Gauge
	bytesTransferred  *prometheus.CounterVec
	rateLimitExceeded prometheus.Counter
	authFailures      prometheus.Counter
	hostBlocked       prometheus.Counter
	upstreamErrors    *prometheus.CounterVec
	registry          *prometheus.Registry
}

// NewMetrics creates and registers Prometheus metrics (singleton pattern)
func NewMetrics() *Metrics {
	metricsOnce.Do(func() {
		registry := prometheus.NewRegistry()

		requestsTotal := prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "proxy_requests_total",
				Help: "Total number of proxy requests",
			},
			[]string{"method", "status"},
		)

		requestDuration := prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "proxy_request_duration_seconds",
				Help:    "Duration of proxy requests in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method"},
		)

		requestsInFlight := prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "proxy_requests_in_flight",
				Help: "Current number of requests being processed",
			},
		)

		tunnelsActive := prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "proxy_tunnels_active",
				Help: "Current number of active HTTPS tunnels",
			},
		)

		bytesTransferred := prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "proxy_bytes_transferred_total",
				Help: "Total bytes transferred through the proxy",
			},
			[]string{"direction"}, // "inbound" or "outbound"
		)

		rateLimitExceeded := prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "proxy_rate_limit_exceeded_total",
				Help: "Total number of requests that exceeded rate limit",
			},
		)

		authFailures := prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "proxy_auth_failures_total",
				Help: "Total number of authentication failures",
			},
		)

		hostBlocked := prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "proxy_host_blocked_total",
				Help: "Total number of blocked host access attempts",
			},
		)

		upstreamErrors := prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "proxy_upstream_errors_total",
				Help: "Total number of upstream connection errors",
			},
			[]string{"type"}, // "connect", "timeout", "other"
		)

		// Register all metrics
		registry.MustRegister(
			requestsTotal,
			requestDuration,
			requestsInFlight,
			tunnelsActive,
			bytesTransferred,
			rateLimitExceeded,
			authFailures,
			hostBlocked,
			upstreamErrors,
		)

		globalMetrics = &Metrics{
			requestsTotal:     requestsTotal,
			requestDuration:   requestDuration,
			requestsInFlight:  requestsInFlight,
			tunnelsActive:     tunnelsActive,
			bytesTransferred:  bytesTransferred,
			rateLimitExceeded: rateLimitExceeded,
			authFailures:      authFailures,
			hostBlocked:       hostBlocked,
			upstreamErrors:    upstreamErrors,
			registry:          registry,
		}
	})

	return globalMetrics
}

// RecordRequest records a completed request
func (m *Metrics) RecordRequest(method string, status int, duration float64) {
	m.requestsTotal.WithLabelValues(method, strconv.Itoa(status)).Inc()
	m.requestDuration.WithLabelValues(method).Observe(duration)
}

// IncrementInFlight increments the in-flight request counter
func (m *Metrics) IncrementInFlight() {
	m.requestsInFlight.Inc()
}

// DecrementInFlight decrements the in-flight request counter
func (m *Metrics) DecrementInFlight() {
	m.requestsInFlight.Dec()
}

// IncrementTunnels increments the active tunnels counter
func (m *Metrics) IncrementTunnels() {
	m.tunnelsActive.Inc()
}

// DecrementTunnels decrements the active tunnels counter
func (m *Metrics) DecrementTunnels() {
	m.tunnelsActive.Dec()
}

// RecordBytesTransferred records bytes transferred
func (m *Metrics) RecordBytesTransferred(direction string, bytes int64) {
	m.bytesTransferred.WithLabelValues(direction).Add(float64(bytes))
}

// RecordRateLimitExceeded records a rate limit exceeded event
func (m *Metrics) RecordRateLimitExceeded() {
	m.rateLimitExceeded.Inc()
}

// RecordAuthFailure records an authentication failure
func (m *Metrics) RecordAuthFailure() {
	m.authFailures.Inc()
}

// RecordHostBlocked records a blocked host access attempt
func (m *Metrics) RecordHostBlocked() {
	m.hostBlocked.Inc()
}

// RecordUpstreamError records an upstream error
func (m *Metrics) RecordUpstreamError(errorType string) {
	m.upstreamErrors.WithLabelValues(errorType).Inc()
}

// Handler returns the Prometheus metrics HTTP handler
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
