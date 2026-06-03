# goMinioProxy

A Go HTTP proxy that sits in front of a single MinIO bucket and enforces fine-grained, per-user access control. Clients connect using standard S3-compatible tooling (AWS SDK, `mc`, etc.) with HMAC SigV4 credentials issued by the proxy.

## How it works

```
Client (AWS SDK / mc)
        │  S3 request + SigV4 headers
        ▼
┌──────────────────────────────────────┐
│             goMinioProxy             │
│                                      │
│  1. Parse SigV4 → extract access key │
│  2. Load user from config            │
│  3. Validate HMAC signature          │
│  4. Parse operation + path           │
│  5. ACL check (prefix + verb)        │
│  6. Re-sign request → MinIO creds    │
│  7. Forward + stream body/response   │
└──────────────────────────────────────┘
        │  re-signed S3 request
        ▼
   Real MinIO server
```

Objects are never buffered in memory — request and response bodies are streamed with `io.Copy`.

## Configuration

```yaml
server:
  address: ":8080"

minio:
  endpoint: "localhost:9000"
  access_key: "minioadmin"
  secret_key: "minioadmin"
  bucket: "my-bucket"
  use_ssl: false
  region: "us-east-1"

users:
  - access_key: "user1key"
    secret_key: "user1secret"
    rules:
      - prefix: "photos/"
        verbs: [get, list]
      - prefix: "uploads/user1/"
        verbs: [get, put, delete, list]

  - access_key: "user2key"
    secret_key: "user2secret"
    rules:
      - prefix: ""      # empty prefix = entire bucket
        verbs: [get, list]
```

### Environment variable overrides

`minio.access_key` and `minio.secret_key` can be overridden at runtime without modifying the config file:

| Variable | Overrides |
|---|---|
| `MINIO_ACCESS_KEY` | `minio.access_key` |
| `MINIO_SECRET_KEY` | `minio.secret_key` |

When set, the environment variable takes precedence over the YAML value. Useful for injecting credentials via Kubernetes Secrets (see [Kubernetes](#kubernetes)).

### Verb mapping

| Verb     | S3 Operations                |
|----------|------------------------------|
| `get`    | GetObject, HeadObject        |
| `put`    | PutObject                    |
| `delete` | DeleteObject                 |
| `list`   | ListObjects, ListObjectsV2   |

A request is allowed when the object key starts with an allowed prefix **and** the operation verb is in that rule's list. Multiple rules per user are OR'd. For `ListObjects`, the requested `prefix` query parameter must fall within an allowed prefix.

## Running

```bash
go build -o bin/gominioproxy .
./bin/gominioproxy                  # uses config.yaml in current directory
./bin/gominioproxy /path/to/config.yaml
```

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

## Testing

Unit tests (no external dependencies):

```bash
go test ./config/... ./acl/... ./auth/... ./proxy/...
```

Integration tests (requires Docker — spins up a real MinIO container):

```bash
go test ./integration/...
```

Integration tests cover: allowed/denied get, put, delete, and list; auth failures (unknown key, bad signature); and a 100 MB streaming test.

## Error responses

All errors are returned as S3-compatible XML:

| Condition           | Error Code              | HTTP Status |
|---------------------|-------------------------|-------------|
| Unknown access key  | `InvalidAccessKeyId`    | 403         |
| Bad HMAC signature  | `SignatureDoesNotMatch` | 403         |
| ACL denied          | `AccessDenied`          | 403         |
| Proxy/upstream error| `InternalError`         | 500         |

## Kubernetes

The proxy handles `SIGTERM` and `SIGINT` by stopping new connections and waiting up to 30 seconds for in-flight requests to drain before exiting.

Because Kubernetes removes the pod from `Endpoints` asynchronously, traffic can still arrive for a few seconds after `SIGTERM` is sent. Add a `preStop` sleep to bridge that gap:

```yaml
lifecycle:
  preStop:
    exec:
      command: ["sleep", "5"]
```

Set `terminationGracePeriodSeconds` to at least `5 + your-max-request-duration`.

### Deployment example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gominioproxy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: gominioproxy
  template:
    metadata:
      labels:
        app: gominioproxy
    spec:
      terminationGracePeriodSeconds: 45   # preStop(5) + max request duration(~30) + buffer
      containers:
        - name: gominioproxy
          image: your-registry/gominioproxy:latest
          args: ["/etc/gominioproxy/config.yaml"]
          ports:
            - containerPort: 8080
          volumeMounts:
            - name: config
              mountPath: /etc/gominioproxy
          env:
            - name: MINIO_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: gominioproxy-minio-creds
                  key: access_key
            - name: MINIO_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: gominioproxy-minio-creds
                  key: secret_key
          lifecycle:
            preStop:
              exec:
                command: ["sleep", "5"]
          readinessProbe:
            tcpSocket:
              port: 8080
            initialDelaySeconds: 3
            periodSeconds: 5
          livenessProbe:
            tcpSocket:
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: 50m
              memory: 32Mi
            limits:
              cpu: 500m
              memory: 128Mi
      volumes:
        - name: config
          configMap:
            name: gominioproxy-config
---
apiVersion: v1
kind: Service
metadata:
  name: gominioproxy
spec:
  selector:
    app: gominioproxy
  ports:
    - port: 80
      targetPort: 8080
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: gominioproxy-config
data:
  config.yaml: |
    server:
      address: ":8080"
    minio:
      endpoint: "minio.minio.svc.cluster.local:9000"
      bucket: "my-bucket"
      use_ssl: false
      region: "us-east-1"
    users:
      - access_key: "user1key"
        secret_key: "user1secret"
        rules:
          - prefix: "photos/"
            verbs: [get, list]
---
apiVersion: v1
kind: Secret
metadata:
  name: gominioproxy-minio-creds
stringData:
  access_key: "minioadmin"
  secret_key: "minioadmin"
```

## Project layout

```
├── main.go
├── metrics/metrics.go     # Recorder interface, PrometheusRecorder, NoopRecorder
├── metrics/metrics_test.go # Unit tests for PrometheusRecorder
├── config/config.go       # YAML config loader + env var overrides (MINIO_ACCESS_KEY, MINIO_SECRET_KEY)
├── config/config_test.go  # Config loading and env var override tests
├── auth/sigv4.go          # SigV4 parsing and HMAC validation
├── acl/acl.go             # Prefix + verb permission checks
├── proxy/proxy.go         # Re-signing and streaming forward
├── server/server.go       # HTTP server + graceful shutdown
├── server/server_test.go  # Graceful shutdown tests
├── integration/           # Integration tests (testcontainers-go)
└── config.yaml            # Example config
```
