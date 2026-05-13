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

## Project layout

```
├── main.go
├── config/config.go       # YAML config loader
├── auth/sigv4.go          # SigV4 parsing and HMAC validation
├── acl/acl.go             # Prefix + verb permission checks
├── proxy/proxy.go         # Re-signing and streaming forward
├── server/server.go       # HTTP server
├── integration/           # Integration tests (testcontainers-go)
└── config.yaml            # Example config
```
