package metrics_test

import (
	"strings"
	"testing"
	"time"

	"gominioproxy/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordRequest(t *testing.T) {
	reg := prometheus.NewRegistry()
	rec := metrics.NewPrometheusRecorder(reg)

	rec.RecordRequest("user1", "get", 200, 50*time.Millisecond)

	expected := `
		# HELP proxy_requests_total Total requests handled by the proxy.
		# TYPE proxy_requests_total counter
		proxy_requests_total{access_key="user1",status_code="200",verb="get"} 1
	`
	assert.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(expected), "proxy_requests_total"))
}

func TestRecordAuthFailure(t *testing.T) {
	reg := prometheus.NewRegistry()
	rec := metrics.NewPrometheusRecorder(reg)

	rec.RecordAuthFailure("unknown_key")
	rec.RecordAuthFailure("bad_signature")
	rec.RecordAuthFailure("bad_signature")

	expected := `
		# HELP proxy_auth_failures_total Authentication failures.
		# TYPE proxy_auth_failures_total counter
		proxy_auth_failures_total{reason="bad_signature"} 2
		proxy_auth_failures_total{reason="unknown_key"} 1
	`
	assert.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(expected), "proxy_auth_failures_total"))
}

func TestRecordACLDenial(t *testing.T) {
	reg := prometheus.NewRegistry()
	rec := metrics.NewPrometheusRecorder(reg)

	rec.RecordACLDenial("user1", "delete")

	expected := `
		# HELP proxy_acl_denials_total Requests denied by ACL.
		# TYPE proxy_acl_denials_total counter
		proxy_acl_denials_total{access_key="user1",verb="delete"} 1
	`
	assert.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(expected), "proxy_acl_denials_total"))
}

func TestInflightGaugeZeroAfterIncrDecr(t *testing.T) {
	reg := prometheus.NewRegistry()
	rec := metrics.NewPrometheusRecorder(reg)

	rec.IncInflight()

	atOne := `
		# HELP proxy_requests_inflight Requests currently being processed.
		# TYPE proxy_requests_inflight gauge
		proxy_requests_inflight 1
	`
	assert.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(atOne), "proxy_requests_inflight"))

	rec.DecInflight()

	atZero := `
		# HELP proxy_requests_inflight Requests currently being processed.
		# TYPE proxy_requests_inflight gauge
		proxy_requests_inflight 0
	`
	assert.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(atZero), "proxy_requests_inflight"))
}

func TestRecordRequestDurationObserved(t *testing.T) {
	reg := prometheus.NewRegistry()
	rec := metrics.NewPrometheusRecorder(reg)

	rec.RecordRequest("user1", "get", 200, 50*time.Millisecond)

	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "proxy_request_duration_seconds" {
			require.Len(t, mf.GetMetric(), 1)
			assert.Equal(t, uint64(1), mf.GetMetric()[0].GetHistogram().GetSampleCount())
			return
		}
	}
	t.Fatal("proxy_request_duration_seconds not found")
}

func TestRecordUpstreamDurationObserved(t *testing.T) {
	reg := prometheus.NewRegistry()
	rec := metrics.NewPrometheusRecorder(reg)

	rec.RecordUpstreamDuration(200, 30*time.Millisecond)

	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "proxy_upstream_duration_seconds" {
			require.Len(t, mf.GetMetric(), 1)
			assert.Equal(t, uint64(1), mf.GetMetric()[0].GetHistogram().GetSampleCount())
			return
		}
	}
	t.Fatal("proxy_upstream_duration_seconds not found")
}
