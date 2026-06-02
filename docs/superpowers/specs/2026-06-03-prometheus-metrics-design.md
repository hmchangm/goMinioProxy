# Prometheus Metrics Design

**Date:** 2026-06-03  
**Status:** Approved

## Overview

Add Prometheus metrics to goMinioProxy, exposed on `/metrics` at the same port as the proxy. Metrics are labeled by `access_key`, `verb`, and `status_code` where applicable. Implementation uses a `metrics.Recorder` interface injected into the proxy, keeping the proxy testable without a real registry.

## Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `proxy_requests_total` | Counter | `access_key`, `verb`, `status_code` | All requests handled by the proxy |
| `proxy_request_duration_seconds` | Histogram | `access_key`, `verb` | End-to-end request latency |
| `proxy_requests_inflight` | Gauge | — | Requests currently being processed |
| `proxy_auth_failures_total` | Counter | `reason` | Auth failures (`unknown_key`, `bad_signature`) |
| `proxy_acl_denials_total` | Counter | `access_key`, `verb` | Requests denied by ACL |
| `proxy_upstream_duration_seconds` | Histogram | `status_code` | Time spent waiting for MinIO |

For requests that fail authentication with an unknown key, `access_key` is set to `"__unknown__"` on `proxy_requests_total` to prevent arbitrary client-supplied values leaking into label cardinality.

## Architecture

### `metrics` package (`metrics/metrics.go`)

```
Recorder interface
    RecordRequest(accessKey, verb string, status int, dur time.Duration)
    RecordAuthFailure(reason string)
    RecordACLDenial(accessKey, verb string)
    RecordUpstreamDuration(status int, dur time.Duration)

PrometheusRecorder struct
    implements Recorder
    constructed with NewPrometheusRecorder(reg prometheus.Registerer)

NoopRecorder struct
    implements Recorder with no-op methods
    used as default when no recorder is injected
```

### `proxy` package changes

- `Proxy` gains a `rec metrics.Recorder` field.
- `proxy.New` defaults `rec` to `NoopRecorder`.
- `proxy.WithRecorder(r metrics.Recorder)` is a functional option to override it.
- A `responseWriter` wrapper intercepts `WriteHeader` to capture the status code for deferred metric recording.

Instrumentation call sites in `ServeHTTP` and `forward`:

| Point | Action |
|---|---|
| Entry | Increment inflight gauge; defer decrement + `RecordRequest` |
| Unknown access key | `RecordAuthFailure("unknown_key")` |
| Bad signature | `RecordAuthFailure("bad_signature")` |
| ACL denial | `RecordACLDenial(accessKey, verb)` |
| After `httpClient.Do` | `RecordUpstreamDuration(upstreamStatus, elapsed)` |

### `main.go` changes

- Create a `prometheus.NewRegistry()` (not the global default — avoids Go runtime collector noise).
- Construct `metrics.NewPrometheusRecorder(reg)` and pass to proxy via `proxy.WithRecorder`.
- Register routes on an `http.ServeMux`:
  - `GET /metrics` → `promhttp.HandlerFor(reg, ...)`
  - All other paths → proxy handler
- Pass the mux as the server handler (replaces the bare proxy).

## Testing

- **`metrics/metrics_test.go`** — unit tests for `PrometheusRecorder`: call each method, gather from the registry, assert counter/gauge/histogram values.
- **`proxy/proxy_test.go`** — existing tests use `NoopRecorder` (default). New cases inject a `PrometheusRecorder` and assert the correct metrics fire for: unknown key, bad signature, ACL denial, successful forward.
- **Integration tests** — no changes; proxy constructs with default noop recorder.

## Dependencies

One new direct dependency: `github.com/prometheus/client_golang`.
