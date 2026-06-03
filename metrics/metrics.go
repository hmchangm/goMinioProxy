package metrics

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Recorder interface {
	IncInflight()
	DecInflight()
	RecordRequest(accessKey, verb string, status int, dur time.Duration)
	RecordAuthFailure(reason string)
	RecordACLDenial(accessKey, verb string)
	RecordUpstreamDuration(status int, dur time.Duration)
}

type PrometheusRecorder struct {
	requests         *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	inflight         prometheus.Gauge
	authFailures     *prometheus.CounterVec
	aclDenials       *prometheus.CounterVec
	upstreamDuration *prometheus.HistogramVec
}

func NewPrometheusRecorder(reg prometheus.Registerer) *PrometheusRecorder {
	r := &PrometheusRecorder{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "proxy_requests_total",
			Help: "Total requests handled by the proxy.",
		}, []string{"access_key", "verb", "status_code"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "proxy_request_duration_seconds",
			Help:    "End-to-end request latency.",
			Buckets: prometheus.DefBuckets,
		}, []string{"access_key", "verb"}),
		inflight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "proxy_requests_inflight",
			Help: "Requests currently being processed.",
		}),
		authFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "proxy_auth_failures_total",
			Help: "Authentication failures.",
		}, []string{"reason"}),
		aclDenials: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "proxy_acl_denials_total",
			Help: "Requests denied by ACL.",
		}, []string{"access_key", "verb"}),
		upstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "proxy_upstream_duration_seconds",
			Help:    "Time spent waiting for MinIO.",
			Buckets: prometheus.DefBuckets,
		}, []string{"status_code"}),
	}
	reg.MustRegister(
		r.requests,
		r.requestDuration,
		r.inflight,
		r.authFailures,
		r.aclDenials,
		r.upstreamDuration,
	)
	return r
}

func (r *PrometheusRecorder) IncInflight() { r.inflight.Inc() }
func (r *PrometheusRecorder) DecInflight() { r.inflight.Dec() }

func (r *PrometheusRecorder) RecordRequest(accessKey, verb string, status int, dur time.Duration) {
	r.requests.WithLabelValues(accessKey, verb, strconv.Itoa(status)).Inc()
	r.requestDuration.WithLabelValues(accessKey, verb).Observe(dur.Seconds())
}

func (r *PrometheusRecorder) RecordAuthFailure(reason string) {
	r.authFailures.WithLabelValues(reason).Inc()
}

func (r *PrometheusRecorder) RecordACLDenial(accessKey, verb string) {
	r.aclDenials.WithLabelValues(accessKey, verb).Inc()
}

func (r *PrometheusRecorder) RecordUpstreamDuration(status int, dur time.Duration) {
	r.upstreamDuration.WithLabelValues(strconv.Itoa(status)).Observe(dur.Seconds())
}

// NoopRecorder implements Recorder with no-op methods. Used as the proxy default.
type NoopRecorder struct{}

func (NoopRecorder) IncInflight()                                       {}
func (NoopRecorder) DecInflight()                                       {}
func (NoopRecorder) RecordRequest(_, _ string, _ int, _ time.Duration) {}
func (NoopRecorder) RecordAuthFailure(_ string)                         {}
func (NoopRecorder) RecordACLDenial(_, _ string)                       {}
func (NoopRecorder) RecordUpstreamDuration(_ int, _ time.Duration)     {}

var _ Recorder = NoopRecorder{}
