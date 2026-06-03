# Prometheus Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose Prometheus metrics on `GET /metrics` (same port as the proxy) tracking request rate, latency, in-flight count, auth failures, ACL denials, and upstream duration.

**Architecture:** A new `metrics` package defines a `Recorder` interface. `PrometheusRecorder` implements it backed by a private `prometheus.Registry`. The proxy accepts a `Recorder` via functional option `WithRecorder`; it defaults to `NoopRecorder` so all existing tests require no changes. `main.go` wires the real recorder and routes `/metrics` through a `ServeMux`.

**Tech Stack:** `github.com/prometheus/client_golang` (prometheus, promhttp, testutil)

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Create | `metrics/metrics.go` | `Recorder` interface, `PrometheusRecorder`, `NoopRecorder` |
| Create | `metrics/metrics_test.go` | Unit tests for `PrometheusRecorder` |
| Modify | `proxy/proxy.go` | `rec` field, `WithRecorder` option, `statusWriter`, instrumentation |
| Modify | `proxy/proxy_test.go` | Four new metric-asserting tests |
| Modify | `main.go` | Registry, recorder, `ServeMux` with `/metrics` route |
| Modify | `README.md` | Document `/metrics` endpoint |

---

## Task 1: Add prometheus dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add the dependency**

```bash
cd /home/brandy/projects/goMinioProxy
/home/brandy/.local/go/bin/go get github.com/prometheus/client_golang@latest
```

Expected: `go.mod` and `go.sum` updated, no errors.

- [ ] **Step 2: Verify build still passes**

```bash
/home/brandy/.local/go/bin/go build ./...
```

Expected: no output (clean build).

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "deps: add prometheus/client_golang"
```

---

## Task 2: Create metrics package

**Files:**
- Create: `metrics/metrics_test.go`
- Create: `metrics/metrics.go`

- [ ] **Step 1: Write the failing tests**

Create `metrics/metrics_test.go`:

```go
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
	rec.DecInflight()

	expected := `
		# HELP proxy_requests_inflight Requests currently being processed.
		# TYPE proxy_requests_inflight gauge
		proxy_requests_inflight 0
	`
	assert.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(expected), "proxy_requests_inflight"))
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
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
/home/brandy/.local/go/bin/go test ./metrics/ -v 2>&1
```

Expected: build failure — `package gominioproxy/metrics: cannot find package`

- [ ] **Step 3: Write the implementation**

Create `metrics/metrics.go`:

```go
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

func (NoopRecorder) IncInflight()                                           {}
func (NoopRecorder) DecInflight()                                           {}
func (NoopRecorder) RecordRequest(_, _ string, _ int, _ time.Duration)     {}
func (NoopRecorder) RecordAuthFailure(_ string)                             {}
func (NoopRecorder) RecordACLDenial(_, _ string)                           {}
func (NoopRecorder) RecordUpstreamDuration(_ int, _ time.Duration)         {}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
/home/brandy/.local/go/bin/go test ./metrics/ -v 2>&1
```

Expected: all 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add metrics/metrics.go metrics/metrics_test.go
git commit -m "feat(metrics): add Recorder interface, PrometheusRecorder, NoopRecorder"
```

---

## Task 3: Instrument the proxy

**Files:**
- Modify: `proxy/proxy_test.go` (add 4 new tests)
- Modify: `proxy/proxy.go` (add `statusWriter`, `WithRecorder`, instrument `ServeHTTP` and `forward`)

- [ ] **Step 1: Write the failing tests**

Append to `proxy/proxy_test.go` (keep existing `package proxy` declaration and imports, add these imports and functions):

```go
import (
	// existing imports stay — add these:
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	"gominioproxy/acl"
	"gominioproxy/config"
	"gominioproxy/metrics"
)
```

> **Note:** The existing file uses `package proxy` (white-box). Keep that. Merge the import block with the existing one — do not duplicate `"testing"` or `"net/http"`.

Add these helper and test functions at the bottom of the file:

```go
func testProxyCfg(minioAddr string) *config.Config {
	return &config.Config{
		MinIO: config.MinIOConfig{
			Endpoint:  minioAddr,
			AccessKey: "miniokey",
			SecretKey: "miniosecret",
			Bucket:    "test-bucket",
			Region:    "us-east-1",
		},
		Users: []config.User{
			{
				AccessKey: "user1key",
				SecretKey: "user1secret",
				Rules:     []config.Rule{{Prefix: "allowed/", Verbs: []string{"get"}}},
			},
		},
	}
}

func signReq(t *testing.T, req *http.Request, accessKey, secretKey string) {
	t.Helper()
	signer := v4.NewSigner()
	creds := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	// SHA-256 of empty body
	err := signer.SignHTTP(context.Background(), creds, req,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"s3", "us-east-1", time.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
}

func TestServeHTTPRecordsMissingAuthAsUnknownKey(t *testing.T) {
	reg := prometheus.NewRegistry()
	rec := metrics.NewPrometheusRecorder(reg)
	p := New(testProxyCfg("localhost:9000"), WithRecorder(rec))

	req := httptest.NewRequest("GET", "/test-bucket/allowed/obj.txt", nil)
	p.ServeHTTP(httptest.NewRecorder(), req)

	expected := `
		# HELP proxy_auth_failures_total Authentication failures.
		# TYPE proxy_auth_failures_total counter
		proxy_auth_failures_total{reason="unknown_key"} 1
	`
	assert.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(expected), "proxy_auth_failures_total"))
}

func TestServeHTTPRecordsBadSignature(t *testing.T) {
	reg := prometheus.NewRegistry()
	rec := metrics.NewPrometheusRecorder(reg)
	p := New(testProxyCfg("localhost:9000"), WithRecorder(rec))

	req := httptest.NewRequest("GET", "/test-bucket/allowed/obj.txt", nil)
	req.Header.Set("Authorization", `AWS4-HMAC-SHA256 Credential=user1key/20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad`)
	req.Header.Set("X-Amz-Date", "20240101T000000Z")
	p.ServeHTTP(httptest.NewRecorder(), req)

	expected := `
		# HELP proxy_auth_failures_total Authentication failures.
		# TYPE proxy_auth_failures_total counter
		proxy_auth_failures_total{reason="bad_signature"} 1
	`
	assert.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(expected), "proxy_auth_failures_total"))
}

func TestServeHTTPRecordsACLDenial(t *testing.T) {
	reg := prometheus.NewRegistry()
	rec := metrics.NewPrometheusRecorder(reg)
	p := New(testProxyCfg("localhost:9000"), WithRecorder(rec))

	// user1key only has GET on allowed/ — request on denied/ is ACL-denied
	req := httptest.NewRequest("GET", "/test-bucket/denied/obj.txt", nil)
	signReq(t, req, "user1key", "user1secret")
	p.ServeHTTP(httptest.NewRecorder(), req)

	expected := `
		# HELP proxy_acl_denials_total Requests denied by ACL.
		# TYPE proxy_acl_denials_total counter
		proxy_acl_denials_total{access_key="user1key",verb="get"} 1
	`
	assert.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(expected), "proxy_acl_denials_total"))
}

func TestServeHTTPRecordsSuccessfulRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	minioAddr := strings.TrimPrefix(upstream.URL, "http://")
	reg := prometheus.NewRegistry()
	rec := metrics.NewPrometheusRecorder(reg)
	p := New(testProxyCfg(minioAddr), WithRecorder(rec))

	req := httptest.NewRequest("GET", "/test-bucket/allowed/obj.txt", nil)
	signReq(t, req, "user1key", "user1secret")
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	expected := `
		# HELP proxy_requests_total Total requests handled by the proxy.
		# TYPE proxy_requests_total counter
		proxy_requests_total{access_key="user1key",status_code="200",verb="get"} 1
	`
	assert.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(expected), "proxy_requests_total"))
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
/home/brandy/.local/go/bin/go test ./proxy/ -v -run "TestServeHTTP" 2>&1
```

Expected: compilation errors — `WithRecorder undefined`, `New` wrong arity.

- [ ] **Step 3: Write the implementation**

Replace the contents of `proxy/proxy.go` with:

```go
// proxy/proxy.go
package proxy

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"gominioproxy/acl"
	"gominioproxy/auth"
	"gominioproxy/config"
	"gominioproxy/metrics"
)

var skipForwardHeaders = map[string]bool{
	"Authorization":        true,
	"X-Amz-Date":          true,
	"X-Amz-Security-Token": true,
}

// statusWriter wraps http.ResponseWriter to capture the written status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if sw.status == 0 {
		sw.status = http.StatusOK
	}
	return sw.ResponseWriter.Write(b)
}

// Proxy implements http.Handler. It validates SigV4, enforces ACL, re-signs, and streams.
type Proxy struct {
	cfg        *config.Config
	userMap    map[string]config.User
	minioBase  string
	httpClient *http.Client
	signer     *v4.Signer
	rec        metrics.Recorder
}

// Option configures a Proxy.
type Option func(*Proxy)

// WithRecorder injects a metrics recorder. Defaults to NoopRecorder.
func WithRecorder(r metrics.Recorder) Option {
	return func(p *Proxy) { p.rec = r }
}

// New constructs a Proxy from cfg.
func New(cfg *config.Config, opts ...Option) *Proxy {
	userMap := make(map[string]config.User, len(cfg.Users))
	for _, u := range cfg.Users {
		userMap[u.AccessKey] = u
	}
	scheme := "http"
	if cfg.MinIO.UseSSL {
		scheme = "https"
	}
	p := &Proxy{
		cfg:       cfg,
		userMap:   userMap,
		minioBase: scheme + "://" + cfg.MinIO.Endpoint,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		signer: v4.NewSigner(),
		rec:    metrics.NoopRecorder{},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func parseOperation(r *http.Request, bucket string) (acl.Verb, string, error) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	bucketName := ""
	if len(parts) > 0 {
		bucketName = parts[0]
	}
	if bucketName != bucket {
		return "", "", fmt.Errorf("unknown bucket %q", bucketName)
	}
	objectKey := ""
	if len(parts) == 2 {
		objectKey = parts[1]
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if objectKey == "" {
			return acl.VerbList, r.URL.Query().Get("prefix"), nil
		}
		return acl.VerbGet, objectKey, nil
	case http.MethodPut:
		if objectKey == "" {
			return "", "", fmt.Errorf("PutObject requires an object key")
		}
		return acl.VerbPut, objectKey, nil
	case http.MethodDelete:
		if objectKey == "" {
			return "", "", fmt.Errorf("DeleteObject requires an object key")
		}
		return acl.VerbDelete, objectKey, nil
	default:
		return "", "", fmt.Errorf("unsupported method %q", r.Method)
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sw := &statusWriter{ResponseWriter: w}
	start := time.Now()
	accessKey := "__unknown__"
	verb := ""

	p.rec.IncInflight()
	defer func() {
		p.rec.DecInflight()
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		p.rec.RecordRequest(accessKey, verb, status, time.Since(start))
	}()

	parsed, err := auth.ParseAuthHeader(r)
	if err != nil {
		writeS3Error(sw, "InvalidAccessKeyId", "Missing or malformed Authorization", http.StatusForbidden)
		p.rec.RecordAuthFailure("unknown_key")
		return
	}

	user, ok := p.userMap[parsed.AccessKey]
	if !ok {
		writeS3Error(sw, "InvalidAccessKeyId", "The access key does not exist", http.StatusForbidden)
		p.rec.RecordAuthFailure("unknown_key")
		return
	}
	accessKey = parsed.AccessKey

	if err := auth.ValidateSignature(r, parsed, user.SecretKey); err != nil {
		writeS3Error(sw, "SignatureDoesNotMatch", "The request signature does not match", http.StatusForbidden)
		p.rec.RecordAuthFailure("bad_signature")
		return
	}

	parsedVerb, aclPath, err := parseOperation(r, p.cfg.MinIO.Bucket)
	if err != nil {
		writeS3Error(sw, "InvalidRequest", err.Error(), http.StatusBadRequest)
		return
	}
	verb = string(parsedVerb)

	if !acl.Check(user, aclPath, parsedVerb) {
		writeS3Error(sw, "AccessDenied", "Access Denied", http.StatusForbidden)
		p.rec.RecordACLDenial(accessKey, verb)
		return
	}

	p.forward(sw, r)
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	upstreamURL := p.minioBase + r.URL.RequestURI()
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		writeS3Error(w, "InternalError", "failed to build upstream request", http.StatusInternalServerError)
		return
	}
	outReq.ContentLength = r.ContentLength

	for k, vs := range r.Header {
		if !skipForwardHeaders[k] {
			outReq.Header[k] = vs
		}
	}
	outReq.Host = p.cfg.MinIO.Endpoint

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}
	creds := aws.Credentials{
		AccessKeyID:     p.cfg.MinIO.AccessKey,
		SecretAccessKey: p.cfg.MinIO.SecretKey,
	}
	region := p.cfg.MinIO.Region
	if region == "" {
		region = "us-east-1"
	}
	if err := p.signer.SignHTTP(r.Context(), creds, outReq, payloadHash, "s3", region, time.Now()); err != nil {
		writeS3Error(w, "InternalError", "failed to sign upstream request", http.StatusInternalServerError)
		return
	}

	upstreamStart := time.Now()
	resp, err := p.httpClient.Do(outReq)
	if err != nil {
		writeS3Error(w, "InternalError", "upstream unreachable", http.StatusInternalServerError)
		return
	}
	p.rec.RecordUpstreamDuration(resp.StatusCode, time.Since(upstreamStart))
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck — client disconnect is non-fatal
}

func writeS3Error(w http.ResponseWriter, code, message string, status int) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	type xmlError struct {
		XMLName   struct{} `xml:"Error"`
		Code      string   `xml:"Code"`
		Message   string   `xml:"Message"`
		RequestID string   `xml:"RequestId"`
	}
	w.Write([]byte(xml.Header)) //nolint:errcheck
	enc := xml.NewEncoder(w)
	enc.Encode(xmlError{Code: code, Message: message, RequestID: "1"}) //nolint:errcheck
}
```

- [ ] **Step 4: Run new tests — verify they pass**

```bash
/home/brandy/.local/go/bin/go test ./proxy/ -v -run "TestServeHTTP" 2>&1
```

Expected: all 4 `TestServeHTTP*` tests PASS.

- [ ] **Step 5: Run all proxy tests — verify no regressions**

```bash
/home/brandy/.local/go/bin/go test ./proxy/ -v 2>&1
```

Expected: all tests PASS (including existing `TestParseOperation`).

- [ ] **Step 6: Commit**

```bash
git add proxy/proxy.go proxy/proxy_test.go
git commit -m "feat(proxy): instrument with Recorder — auth failures, ACL denials, request metrics"
```

---

## Task 4: Wire metrics into main.go

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Replace main.go**

```go
package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"gominioproxy/config"
	"gominioproxy/metrics"
	"gominioproxy/proxy"
	"gominioproxy/server"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	cfgPath := "config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ln, err := net.Listen("tcp", cfg.Server.Address)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	reg := prometheus.NewRegistry()
	rec := metrics.NewPrometheusRecorder(reg)

	p := proxy.New(cfg, proxy.WithRecorder(rec))

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.Handle("/", p)

	srv := server.New(cfg, mux)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Printf("proxy listening on %s → minio %s/%s", cfg.Server.Address, cfg.MinIO.Endpoint, cfg.MinIO.Bucket)
	if err := server.Run(ctx, srv, ln); err != nil {
		log.Fatalf("server: %v", err)
	}
	log.Println("shutdown complete")
}
```

- [ ] **Step 2: Build and run all tests**

```bash
/home/brandy/.local/go/bin/go build ./... && /home/brandy/.local/go/bin/go test ./... 2>&1
```

Expected: clean build, all packages PASS (integration tests will take ~10 s).

- [ ] **Step 3: Commit**

```bash
git add main.go
git commit -m "feat: wire Prometheus metrics into main — /metrics on same port"
```

---

## Task 5: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a Metrics section after Running**

Find the `## Testing` heading and insert before it:

```markdown
## Metrics

The proxy exposes Prometheus metrics at `GET /metrics` on the same port as the proxy (no extra configuration).

| Metric | Type | Labels |
|---|---|---|
| `proxy_requests_total` | Counter | `access_key`, `verb`, `status_code` |
| `proxy_request_duration_seconds` | Histogram | `access_key`, `verb` |
| `proxy_requests_inflight` | Gauge | — |
| `proxy_auth_failures_total` | Counter | `reason` |
| `proxy_acl_denials_total` | Counter | `access_key`, `verb` |
| `proxy_upstream_duration_seconds` | Histogram | `status_code` |

`access_key` is set to `__unknown__` for requests that fail with an unrecognised key, preventing arbitrary client-supplied values from polluting label cardinality.

To scrape with Prometheus add the proxy service as a target. The Kubernetes deployment example already exposes port 80; add an annotation or `ServiceMonitor` pointing to `path: /metrics`.
```

- [ ] **Step 2: Update project layout**

In the project layout code block, add the new package:

```
├── metrics/metrics.go     # Recorder interface, PrometheusRecorder, NoopRecorder
├── metrics/metrics_test.go # Unit tests for PrometheusRecorder
```

- [ ] **Step 3: Commit and push**

```bash
git add README.md
git commit -m "docs: add Prometheus metrics section and project layout entries"
git push
```
