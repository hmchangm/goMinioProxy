# MinIO Proxy — Design Spec

**Date:** 2026-05-13  
**Status:** Approved

## Overview

A Go HTTP proxy that sits in front of a single real MinIO bucket and enforces fine-grained, per-user access control rules. Clients connect using standard S3-compatible tooling (AWS SDK, `mc`, etc.) with HMAC SigV4 credentials issued by the proxy. The proxy validates signatures, applies ACL rules (prefix + operation scoped), re-signs requests with real MinIO credentials, and streams data bidirectionally without buffering objects in memory.

---

## Architecture & Request Flow

```
Client (AWS SDK / mc)
        │  S3 request + SigV4 headers
        ▼
┌──────────────────────────────────────┐
│             Go Proxy                 │
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

**Streaming constraint:** `io.Copy` is used for both request and response bodies. Objects are never buffered in memory. PutObject pipes `req.Body` directly upstream; GetObject pipes MinIO's response body directly to the client writer.

---

## Package Structure

```
goMinioProxy/
├── main.go                  # entry point, wires everything
├── config/
│   └── config.go            # load & validate YAML config
├── auth/
│   └── sigv4.go             # parse + validate incoming SigV4
├── acl/
│   └── acl.go               # check user permissions (prefix + verb)
├── proxy/
│   └── proxy.go             # re-sign + stream request to MinIO
├── server/
│   └── server.go            # HTTP server, routes to proxy handler
├── config.yaml              # example config (users + rules)
└── integration/
    ├── setup_test.go        # testcontainers MinIO setup + proxy boot
    ├── get_test.go          # GetObject scenarios
    ├── put_test.go          # PutObject scenarios
    ├── delete_test.go       # DeleteObject scenarios
    └── list_test.go         # ListObjects scenarios
```

---

## Config Format

```yaml
server:
  address: ":8080"

minio:
  endpoint: "localhost:9000"
  access_key: "minioadmin"
  secret_key: "minioadmin"
  bucket: "my-bucket"
  use_ssl: false

users:
  - access_key: "user1key"
    secret_key: "user1secret"
    rules:
      - prefix: "photos/"
        verbs: ["get", "list"]
      - prefix: "uploads/user1/"
        verbs: ["get", "put", "delete", "list"]

  - access_key: "user2key"
    secret_key: "user2secret"
    rules:
      - prefix: ""          # empty prefix = entire bucket
        verbs: ["get", "list"]
```

### Verb Mapping

| Verb     | S3 Operations                  |
|----------|-------------------------------|
| `get`    | GetObject, HeadObject         |
| `put`    | PutObject                     |
| `delete` | DeleteObject                  |
| `list`   | ListObjects, ListObjectsV2    |

A request is allowed if the object key starts with an allowed prefix **and** the operation verb is in that rule's verb list. Multiple rules per user are OR'd.

For `ListObjects`, the requested `prefix` query parameter must start with (or equal) one of the user's allowed prefixes — it cannot be broadened to list outside allowed paths.

---

## Supported S3 Operations

Basic CRUD only:

- `GetObject`
- `HeadObject`
- `PutObject`
- `DeleteObject`
- `ListObjects` / `ListObjectsV2`

---

## Error Handling & Security

### Auth Failures (S3 XML error responses)

| Condition | S3 Error Code | HTTP Status |
|-----------|--------------|-------------|
| Unknown access key | `InvalidAccessKeyId` | 403 |
| Bad HMAC signature | `SignatureDoesNotMatch` | 403 |
| ACL denied | `AccessDenied` | 403 |

### Proxy Errors

MinIO unreachable or unexpected response → `InternalError` (500). No internal details leaked.

### Security

- Secrets are never logged.
- `Host` and `Authorization` headers stripped before re-signing — no credential leakage to MinIO.
- Full SigV4 validation: signed headers + body hash — no partial validation shortcuts.

### Streaming Error Handling

- MinIO error responses (non-2xx) are forwarded as-is (already S3 XML).
- If client disconnects mid-stream during PutObject, the upstream request is cancelled via context cancellation — no dangling uploads.

---

## Testing Strategy

Integration tests only — no mocks. All tests run against a real MinIO container via `testcontainers-go`.

### Setup

1. `testcontainers-go` spins up `minio/minio` container.
2. Proxy starts on a random free port pointed at the container.
3. Tests use `aws-sdk-go-v2` S3 client pointed at the proxy.
4. Container and proxy tear down after each test suite.

### Test Scenarios

| Test | What it verifies |
|------|-----------------|
| Allowed `GetObject` | User with `get` on matching prefix succeeds |
| Denied `GetObject` | User without `get` on that prefix gets 403 |
| Allowed `PutObject` | Upload streams correctly, object appears in MinIO |
| Denied `PutObject` | User without `put` gets 403 |
| Allowed `ListObjects` | Returns only objects under allowed prefix |
| Denied `ListObjects` | User without `list` gets 403 |
| `DeleteObject` allowed/denied | Same pattern |
| Bad credentials | Wrong secret → 403 `SignatureDoesNotMatch` |
| Unknown access key | → 403 `InvalidAccessKeyId` |
| Large object streaming | 100MB PUT/GET completes without OOM |

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/aws/aws-sdk-go-v2/aws/signer/v4` | SigV4 parsing and re-signing |
| `github.com/aws/aws-sdk-go-v2/service/s3` | S3 client for integration tests |
| `gopkg.in/yaml.v3` | Config file parsing |
| `github.com/testcontainers/testcontainers-go` | MinIO container for integration tests |
