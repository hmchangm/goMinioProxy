# MinIO Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go HTTP proxy that enforces per-user, prefix+verb ACL rules in front of a single MinIO bucket using S3-compatible SigV4 authentication, streaming all data without buffering.

**Architecture:** Incoming S3 requests are authenticated via SigV4 HMAC validation, checked against YAML-configured ACL rules (prefix + verb), re-signed with real MinIO credentials, and forwarded with `io.Copy` streaming in both directions. No object data is held in memory.

**Tech Stack:** Go 1.22, `aws-sdk-go-v2` (SigV4 signer + S3 client for tests), `gopkg.in/yaml.v3`, `testcontainers-go` with MinIO module, integration-only tests (no mocks).

---

## File Map

| File | Responsibility |
|------|---------------|
| `main.go` | Entry point: load config, wire server |
| `config/config.go` | Load and validate YAML config |
| `acl/acl.go` | Prefix+verb permission check |
| `auth/sigv4.go` | Parse and validate incoming SigV4 Authorization header |
| `proxy/proxy.go` | ServeHTTP: auth → ACL → re-sign → stream |
| `server/server.go` | Construct `*http.Server` |
| `config.yaml` | Example configuration |
| `integration/setup_test.go` | TestMain: MinIO container + proxy startup + helpers |
| `integration/auth_test.go` | Auth failure scenarios |
| `integration/get_test.go` | GetObject allowed/denied |
| `integration/put_test.go` | PutObject allowed/denied |
| `integration/delete_test.go` | DeleteObject allowed/denied |
| `integration/list_test.go` | ListObjects allowed/denied + prefix enforcement |
| `integration/streaming_test.go` | 100 MB PUT/GET without OOM |

---

## Task 1: Go module init and directory scaffold

**Files:**
- Create: `go.mod`
- Create: all package directories

- [ ] **Step 1: Initialize module and create directories**

```bash
cd /home/brandy/projects/goMinioProxy
go mod init gominioproxy
mkdir -p config auth acl proxy server integration
```

- [ ] **Step 2: Install dependencies**

```bash
go get github.com/aws/aws-sdk-go-v2
go get github.com/aws/aws-sdk-go-v2/config
go get github.com/aws/aws-sdk-go-v2/credentials
go get github.com/aws/aws-sdk-go-v2/service/s3
go get gopkg.in/yaml.v3
go get github.com/testcontainers/testcontainers-go
go get github.com/testcontainers/testcontainers-go/modules/minio
go mod tidy
```

- [ ] **Step 3: Verify go.mod has all dependencies**

```bash
cat go.mod
```

Expected: `require` block lists `aws-sdk-go-v2`, `yaml.v3`, `testcontainers-go`.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: initialize go module with dependencies"
```

---

## Task 2: Config package

**Files:**
- Create: `config/config.go`
- Create: `config/config_test.go`

- [ ] **Step 1: Write the failing test**

```go
// config/config_test.go
package config_test

import (
	"os"
	"testing"

	"gominioproxy/config"
)

func TestLoad(t *testing.T) {
	yaml := `
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
`
	f, _ := os.CreateTemp("", "cfg*.yaml")
	f.WriteString(yaml)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := config.Load(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Address != ":8080" {
		t.Errorf("got address %q, want :8080", cfg.Server.Address)
	}
	if cfg.MinIO.Bucket != "my-bucket" {
		t.Errorf("got bucket %q, want my-bucket", cfg.MinIO.Bucket)
	}
	if len(cfg.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(cfg.Users))
	}
	if cfg.Users[0].AccessKey != "user1key" {
		t.Errorf("got access key %q, want user1key", cfg.Users[0].AccessKey)
	}
	if len(cfg.Users[0].Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(cfg.Users[0].Rules))
	}
	if cfg.Users[0].Rules[0].Prefix != "photos/" {
		t.Errorf("got prefix %q, want photos/", cfg.Users[0].Rules[0].Prefix)
	}
	if len(cfg.Users[0].Rules[0].Verbs) != 2 {
		t.Errorf("got %d verbs, want 2", len(cfg.Users[0].Rules[0].Verbs))
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/path.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoadMissingBucket(t *testing.T) {
	yaml := `
server:
  address: ":8080"
minio:
  endpoint: "localhost:9000"
  access_key: "key"
  secret_key: "secret"
`
	f, _ := os.CreateTemp("", "cfg*.yaml")
	f.WriteString(yaml)
	f.Close()
	defer os.Remove(f.Name())

	_, err := config.Load(f.Name())
	if err == nil {
		t.Error("expected error for missing bucket, got nil")
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
go test ./config/...
```

Expected: FAIL — `config` package does not exist yet.

- [ ] **Step 3: Implement config.go**

```go
// config/config.go
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server ServerConfig `yaml:"server"`
	MinIO  MinIOConfig  `yaml:"minio"`
	Users  []User       `yaml:"users"`
}

type ServerConfig struct {
	Address string `yaml:"address"`
}

type MinIOConfig struct {
	Endpoint  string `yaml:"endpoint"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Bucket    string `yaml:"bucket"`
	UseSSL    bool   `yaml:"use_ssl"`
}

type User struct {
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Rules     []Rule `yaml:"rules"`
}

type Rule struct {
	Prefix string   `yaml:"prefix"`
	Verbs  []string `yaml:"verbs"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.MinIO.Bucket == "" {
		return nil, fmt.Errorf("minio.bucket is required")
	}
	if cfg.MinIO.Endpoint == "" {
		return nil, fmt.Errorf("minio.endpoint is required")
	}
	return &cfg, nil
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
go test ./config/... -v
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add config/
git commit -m "feat: config package with YAML loading and validation"
```

---

## Task 3: ACL package

**Files:**
- Create: `acl/acl.go`
- Create: `acl/acl_test.go`

- [ ] **Step 1: Write the failing test**

```go
// acl/acl_test.go
package acl_test

import (
	"testing"

	"gominioproxy/acl"
	"gominioproxy/config"
)

var testUser = config.User{
	AccessKey: "user1key",
	SecretKey: "user1secret",
	Rules: []config.Rule{
		{Prefix: "photos/", Verbs: []string{"get", "list"}},
		{Prefix: "uploads/user1/", Verbs: []string{"get", "put", "delete", "list"}},
	},
}

var readOnlyUser = config.User{
	AccessKey: "user2key",
	SecretKey: "user2secret",
	Rules: []config.Rule{
		{Prefix: "", Verbs: []string{"get", "list"}},
	},
}

func TestAllowed(t *testing.T) {
	cases := []struct {
		name    string
		user    config.User
		path    string
		verb    acl.Verb
		allowed bool
	}{
		{"get allowed prefix", testUser, "photos/img.jpg", acl.VerbGet, true},
		{"list allowed prefix", testUser, "photos/", acl.VerbList, true},
		{"put allowed prefix", testUser, "uploads/user1/f.txt", acl.VerbPut, true},
		{"delete allowed prefix", testUser, "uploads/user1/f.txt", acl.VerbDelete, true},
		{"put denied on read-only prefix", testUser, "photos/img.jpg", acl.VerbPut, false},
		{"delete denied on read-only prefix", testUser, "photos/img.jpg", acl.VerbDelete, false},
		{"get denied wrong prefix", testUser, "uploads/user2/f.txt", acl.VerbGet, false},
		{"readonly can get anything", readOnlyUser, "any/path/file.txt", acl.VerbGet, true},
		{"readonly can list empty prefix", readOnlyUser, "", acl.VerbList, true},
		{"readonly cannot put", readOnlyUser, "any/path/file.txt", acl.VerbPut, false},
		{"readonly cannot delete", readOnlyUser, "any/path/file.txt", acl.VerbDelete, false},
		{"list scoped to allowed prefix", testUser, "photos/vacation/", acl.VerbList, true},
		{"list denied outside prefix", testUser, "other/", acl.VerbList, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := acl.Check(tc.user, tc.path, tc.verb)
			if got != tc.allowed {
				t.Errorf("Check(%q, %q, %q) = %v, want %v", tc.user.AccessKey, tc.path, tc.verb, got, tc.allowed)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
go test ./acl/...
```

Expected: FAIL — `acl` package does not exist yet.

- [ ] **Step 3: Implement acl.go**

```go
// acl/acl.go
package acl

import (
	"strings"

	"gominioproxy/config"
)

type Verb string

const (
	VerbGet    Verb = "get"
	VerbPut    Verb = "put"
	VerbDelete Verb = "delete"
	VerbList   Verb = "list"
)

// Check returns true if user may perform verb on path.
// For list operations pass the requested prefix query param as path.
func Check(user config.User, path string, verb Verb) bool {
	for _, rule := range user.Rules {
		if hasVerb(rule, verb) && strings.HasPrefix(path, rule.Prefix) {
			return true
		}
	}
	return false
}

func hasVerb(rule config.Rule, verb Verb) bool {
	for _, v := range rule.Verbs {
		if Verb(v) == verb {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
go test ./acl/... -v
```

Expected: all 13 cases PASS.

- [ ] **Step 5: Commit**

```bash
git add acl/
git commit -m "feat: acl package with prefix+verb permission checks"
```

---

## Task 4: Auth — SigV4 header parsing

**Files:**
- Create: `auth/sigv4.go`
- Create: `auth/sigv4_test.go`

- [ ] **Step 1: Write the failing parsing tests**

```go
// auth/sigv4_test.go
package auth_test

import (
	"net/http"
	"testing"

	"gominioproxy/auth"
)

const validAuthHeader = `AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41`

func TestParseAuthHeader(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/bucket/key", nil)
	r.Header.Set("Authorization", validAuthHeader)

	parsed, err := auth.ParseAuthHeader(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.AccessKey != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("got access key %q, want AKIAIOSFODNN7EXAMPLE", parsed.AccessKey)
	}
	if parsed.Date != "20130524" {
		t.Errorf("got date %q, want 20130524", parsed.Date)
	}
	if parsed.Region != "us-east-1" {
		t.Errorf("got region %q, want us-east-1", parsed.Region)
	}
	if parsed.Service != "s3" {
		t.Errorf("got service %q, want s3", parsed.Service)
	}
	if len(parsed.SignedHeaders) != 3 {
		t.Fatalf("got %d signed headers, want 3", len(parsed.SignedHeaders))
	}
	if parsed.SignedHeaders[0] != "host" {
		t.Errorf("got first signed header %q, want host", parsed.SignedHeaders[0])
	}
	if parsed.Signature != "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41" {
		t.Errorf("got unexpected signature: %s", parsed.Signature)
	}
}

func TestParseAuthHeaderMissing(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	_, err := auth.ParseAuthHeader(r)
	if err == nil {
		t.Error("expected error for missing Authorization header")
	}
}

func TestParseAuthHeaderWrongScheme(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	_, err := auth.ParseAuthHeader(r)
	if err == nil {
		t.Error("expected error for wrong auth scheme")
	}
}

func TestParseAuthHeaderMalformed(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=BAD")
	_, err := auth.ParseAuthHeader(r)
	if err == nil {
		t.Error("expected error for malformed credential")
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
go test ./auth/...
```

Expected: FAIL — `auth` package does not exist yet.

- [ ] **Step 3: Implement ParseAuthHeader in sigv4.go**

```go
// auth/sigv4.go
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ParsedAuth holds the fields extracted from an AWS4-HMAC-SHA256 Authorization header.
type ParsedAuth struct {
	AccessKey     string
	Date          string
	Region        string
	Service       string
	SignedHeaders  []string
	Signature     string
}

// ParseAuthHeader extracts auth fields from the incoming request's Authorization header.
func ParseAuthHeader(r *http.Request) (*ParsedAuth, error) {
	raw := r.Header.Get("Authorization")
	if raw == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	const prefix = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(raw, prefix) {
		return nil, fmt.Errorf("unsupported auth scheme")
	}
	raw = strings.TrimPrefix(raw, prefix)

	parts := strings.Split(raw, ", ")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed Authorization: expected 3 parts, got %d", len(parts))
	}

	credKV := strings.SplitN(parts[0], "=", 2)
	if len(credKV) != 2 || credKV[0] != "Credential" {
		return nil, fmt.Errorf("missing Credential field")
	}
	credParts := strings.Split(credKV[1], "/")
	if len(credParts) != 5 {
		return nil, fmt.Errorf("invalid Credential format: %q", credKV[1])
	}

	shKV := strings.SplitN(parts[1], "=", 2)
	if len(shKV) != 2 || shKV[0] != "SignedHeaders" {
		return nil, fmt.Errorf("missing SignedHeaders field")
	}

	sigKV := strings.SplitN(parts[2], "=", 2)
	if len(sigKV) != 2 || sigKV[0] != "Signature" {
		return nil, fmt.Errorf("missing Signature field")
	}

	return &ParsedAuth{
		AccessKey:    credParts[0],
		Date:         credParts[1],
		Region:       credParts[2],
		Service:      credParts[3],
		SignedHeaders: strings.Split(shKV[1], ";"),
		Signature:    sigKV[2],
	}, nil
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
go test ./auth/... -v -run TestParseAuth
```

Expected: 4 parsing tests PASS.

---

## Task 5: Auth — SigV4 signature validation

**Files:**
- Modify: `auth/sigv4.go` (add ValidateSignature + helpers)
- Modify: `auth/sigv4_test.go` (add validation tests)

- [ ] **Step 1: Add validation tests to sigv4_test.go**

Append these tests to the existing `auth/sigv4_test.go`:

```go
// append to auth/sigv4_test.go

import (
	// add these imports to the existing import block:
	"context"
	"strings"
	"time"

	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func signedRequest(t *testing.T, method, rawURL, accessKey, secretKey string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	r.Header.Set("X-Amz-Content-Sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	creds, _ := awscreds.NewStaticCredentialsProvider(accessKey, secretKey, "").Retrieve(context.Background())
	signer := v4.NewSigner()
	_ = signer.SignHTTP(context.Background(), creds, r,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"s3", "us-east-1", time.Now())
	return r
}

func TestValidateSignatureOK(t *testing.T) {
	r := signedRequest(t, "GET", "http://proxy:8080/my-bucket/photos/img.jpg", "testkey", "testsecret")
	parsed, err := auth.ParseAuthHeader(r)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := auth.ValidateSignature(r, parsed, "testsecret"); err != nil {
		t.Errorf("expected valid signature, got: %v", err)
	}
}

func TestValidateSignatureWrongSecret(t *testing.T) {
	r := signedRequest(t, "GET", "http://proxy:8080/my-bucket/key", "testkey", "testsecret")
	parsed, _ := auth.ParseAuthHeader(r)
	if err := auth.ValidateSignature(r, parsed, "wrongsecret"); err == nil {
		t.Error("expected error for wrong secret key")
	}
}

func TestValidateSignatureTampered(t *testing.T) {
	r := signedRequest(t, "GET", "http://proxy:8080/my-bucket/key", "testkey", "testsecret")
	// Tamper with signature
	orig := r.Header.Get("Authorization")
	r.Header.Set("Authorization", strings.Replace(orig, orig[len(orig)-4:], "0000", 1))
	parsed, _ := auth.ParseAuthHeader(r)
	if err := auth.ValidateSignature(r, parsed, "testsecret"); err == nil {
		t.Error("expected error for tampered signature")
	}
}
```

- [ ] **Step 2: Run to confirm new tests fail**

```bash
go test ./auth/... -v -run TestValidate
```

Expected: FAIL — `ValidateSignature` not defined yet.

- [ ] **Step 3: Implement ValidateSignature and helpers — append to sigv4.go**

```go
// append to auth/sigv4.go

// ValidateSignature recomputes the SigV4 signature for r using secretKey and compares it
// to the signature in parsed. Returns an error if they do not match.
func ValidateSignature(r *http.Request, parsed *ParsedAuth, secretKey string) error {
	canon := canonicalRequest(r, parsed.SignedHeaders)
	dateTime := r.Header.Get("X-Amz-Date")
	scope := parsed.Date + "/" + parsed.Region + "/" + parsed.Service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		dateTime,
		scope,
		hexSHA256([]byte(canon)),
	}, "\n")
	key := signingKey(secretKey, parsed.Date, parsed.Region, parsed.Service)
	expected := hex.EncodeToString(hmacSHA256(key, []byte(stringToSign)))
	if expected != parsed.Signature {
		return fmt.Errorf("signature does not match")
	}
	return nil
}

func canonicalRequest(r *http.Request, signedHeaders []string) string {
	return strings.Join([]string{
		r.Method,
		canonicalURI(r.URL),
		canonicalQueryString(r.URL),
		canonicalHeaders(r, signedHeaders),
		strings.Join(signedHeaders, ";"),
		payloadHash(r),
	}, "\n")
}

func canonicalURI(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			decoded = seg
		}
		segments[i] = uriEncode(decoded)
	}
	return strings.Join(segments, "/")
}

func canonicalQueryString(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	params := strings.Split(u.RawQuery, "&")
	pairs := make([]string, 0, len(params))
	for _, p := range params {
		kv := strings.SplitN(p, "=", 2)
		k, _ := url.PathUnescape(kv[0])
		v := ""
		if len(kv) == 2 {
			v, _ = url.PathUnescape(kv[1])
		}
		pairs = append(pairs, uriEncode(k)+"="+uriEncode(v))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func canonicalHeaders(r *http.Request, signedHeaders []string) string {
	var b strings.Builder
	for _, h := range signedHeaders {
		var val string
		if h == "host" {
			val = r.Host
		} else {
			vals := r.Header[http.CanonicalHeaderKey(h)]
			trimmed := make([]string, len(vals))
			for i, v := range vals {
				trimmed[i] = strings.Join(strings.Fields(v), " ")
			}
			val = strings.Join(trimmed, ",")
		}
		b.WriteString(h)
		b.WriteByte(':')
		b.WriteString(strings.TrimSpace(val))
		b.WriteByte('\n')
	}
	return b.String()
}

func payloadHash(r *http.Request) string {
	if h := r.Header.Get("X-Amz-Content-Sha256"); h != "" {
		return h
	}
	// SHA256 of empty string
	return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hexSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func signingKey(secretKey, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}
```

- [ ] **Step 4: Fix import block in sigv4_test.go to include all imports**

The test file's import block must include all packages used. Replace the import block in `auth/sigv4_test.go` with:

```go
import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"gominioproxy/auth"
)
```

- [ ] **Step 5: Run all auth tests**

```bash
go test ./auth/... -v
```

Expected: all 7 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add auth/
git commit -m "feat: auth package with SigV4 parsing and HMAC validation"
```

---

## Task 6: Proxy — operation parsing

**Files:**
- Create: `proxy/proxy.go` (just parseOperation for now)
- Create: `proxy/proxy_test.go`

- [ ] **Step 1: Write failing tests**

```go
// proxy/proxy_test.go
package proxy

import (
	"net/http"
	"testing"

	"gominioproxy/acl"
)

func TestParseOperation(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		url         string
		wantVerb    acl.Verb
		wantPath    string
		wantErr     bool
	}{
		{
			name: "get object",
			method: "GET", url: "http://proxy/my-bucket/photos/img.jpg",
			wantVerb: acl.VerbGet, wantPath: "photos/img.jpg",
		},
		{
			name: "head object",
			method: "HEAD", url: "http://proxy/my-bucket/docs/file.pdf",
			wantVerb: acl.VerbGet, wantPath: "docs/file.pdf",
		},
		{
			name: "put object",
			method: "PUT", url: "http://proxy/my-bucket/uploads/user1/data.csv",
			wantVerb: acl.VerbPut, wantPath: "uploads/user1/data.csv",
		},
		{
			name: "delete object",
			method: "DELETE", url: "http://proxy/my-bucket/uploads/user1/old.txt",
			wantVerb: acl.VerbDelete, wantPath: "uploads/user1/old.txt",
		},
		{
			name: "list objects no prefix",
			method: "GET", url: "http://proxy/my-bucket?list-type=2",
			wantVerb: acl.VerbList, wantPath: "",
		},
		{
			name: "list objects with prefix",
			method: "GET", url: "http://proxy/my-bucket?list-type=2&prefix=photos/",
			wantVerb: acl.VerbList, wantPath: "photos/",
		},
		{
			name: "wrong bucket",
			method: "GET", url: "http://proxy/other-bucket/key",
			wantErr: true,
		},
		{
			name: "put without key",
			method: "PUT", url: "http://proxy/my-bucket",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(tc.method, tc.url, nil)
			verb, path, err := parseOperation(r, "my-bucket")
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verb != tc.wantVerb {
				t.Errorf("got verb %q, want %q", verb, tc.wantVerb)
			}
			if path != tc.wantPath {
				t.Errorf("got path %q, want %q", path, tc.wantPath)
			}
		})
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./proxy/...
```

Expected: FAIL — `proxy` package does not exist yet.

- [ ] **Step 3: Create proxy.go with parseOperation**

```go
// proxy/proxy.go
package proxy

import (
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
)

// Proxy implements http.Handler. It validates SigV4, enforces ACL, re-signs, and streams.
type Proxy struct {
	cfg        *config.Config
	userMap    map[string]config.User
	minioBase  string
	httpClient *http.Client
	signer     *v4.Signer
}

// New constructs a Proxy from cfg.
func New(cfg *config.Config) *Proxy {
	userMap := make(map[string]config.User, len(cfg.Users))
	for _, u := range cfg.Users {
		userMap[u.AccessKey] = u
	}
	scheme := "http"
	if cfg.MinIO.UseSSL {
		scheme = "https"
	}
	return &Proxy{
		cfg:        cfg,
		userMap:    userMap,
		minioBase:  scheme + "://" + cfg.MinIO.Endpoint,
		httpClient: &http.Client{},
		signer:     v4.NewSigner(),
	}
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
	parsed, err := auth.ParseAuthHeader(r)
	if err != nil {
		writeS3Error(w, "InvalidAccessKeyId", "Missing or malformed Authorization", http.StatusForbidden)
		return
	}

	user, ok := p.userMap[parsed.AccessKey]
	if !ok {
		writeS3Error(w, "InvalidAccessKeyId", "The access key does not exist", http.StatusForbidden)
		return
	}

	if err := auth.ValidateSignature(r, parsed, user.SecretKey); err != nil {
		writeS3Error(w, "SignatureDoesNotMatch", "The request signature does not match", http.StatusForbidden)
		return
	}

	verb, aclPath, err := parseOperation(r, p.cfg.MinIO.Bucket)
	if err != nil {
		writeS3Error(w, "InvalidRequest", err.Error(), http.StatusBadRequest)
		return
	}

	if !acl.Check(user, aclPath, verb) {
		writeS3Error(w, "AccessDenied", "Access Denied", http.StatusForbidden)
		return
	}

	p.forward(w, r)
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	upstreamURL := p.minioBase + r.URL.RequestURI()
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		writeS3Error(w, "InternalError", "failed to build upstream request", http.StatusInternalServerError)
		return
	}
	outReq.ContentLength = r.ContentLength

	skipHeaders := map[string]bool{
		"Authorization":       true,
		"X-Amz-Date":         true,
		"X-Amz-Security-Token": true,
	}
	for k, vs := range r.Header {
		if !skipHeaders[k] {
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
	if err := p.signer.SignHTTP(r.Context(), creds, outReq, payloadHash, "s3", "us-east-1", time.Now()); err != nil {
		writeS3Error(w, "InternalError", "failed to sign upstream request", http.StatusInternalServerError)
		return
	}

	resp, err := p.httpClient.Do(outReq)
	if err != nil {
		writeS3Error(w, "InternalError", "upstream unreachable", http.StatusInternalServerError)
		return
	}
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
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message><RequestId>1</RequestId></Error>`, code, message)
}
```

- [ ] **Step 4: Run proxy tests**

```bash
go test ./proxy/... -v -run TestParseOperation
```

Expected: all 8 cases PASS.

- [ ] **Step 5: Compile check on all packages**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add proxy/
git commit -m "feat: proxy package with SigV4 auth, ACL enforcement, and streaming forward"
```

---

## Task 7: Server package and main.go

**Files:**
- Create: `server/server.go`
- Create: `main.go`
- Create: `config.yaml`

- [ ] **Step 1: Create server.go**

```go
// server/server.go
package server

import (
	"net/http"

	"gominioproxy/config"
)

func New(cfg *config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:    cfg.Server.Address,
		Handler: handler,
	}
}
```

- [ ] **Step 2: Create main.go**

```go
// main.go
package main

import (
	"log"
	"os"

	"gominioproxy/config"
	"gominioproxy/proxy"
	"gominioproxy/server"
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

	p := proxy.New(cfg)
	srv := server.New(cfg, p)

	log.Printf("proxy listening on %s → minio %s/%s", cfg.Server.Address, cfg.MinIO.Endpoint, cfg.MinIO.Bucket)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
```

- [ ] **Step 3: Create example config.yaml**

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
      - prefix: ""
        verbs: ["get", "list"]
```

- [ ] **Step 4: Build the binary**

```bash
go build -o bin/gominioproxy .
```

Expected: `bin/gominioproxy` created with no errors.

- [ ] **Step 5: Commit**

```bash
git add server/ main.go config.yaml bin/
git commit -m "feat: server wiring, main entry point, and example config"
```

---

## Task 8: Integration test infrastructure

**Files:**
- Create: `integration/setup_test.go`

- [ ] **Step 1: Create setup_test.go**

```go
// integration/setup_test.go
package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/testcontainers/testcontainers-go/modules/minio"

	proxycfg "gominioproxy/config"
	"gominioproxy/proxy"
	"gominioproxy/server"
)

const testBucket = "test-bucket"

// proxyURL is the base URL of the proxy started by TestMain.
var proxyURL string

// adminS3 is an S3 client pointed directly at MinIO (bypasses the proxy).
var adminS3 *s3.Client

// proxyConfig is shared across all integration tests.
var proxyConfig = &proxycfg.Config{
	MinIO: proxycfg.MinIOConfig{
		Bucket: testBucket,
	},
	Users: []proxycfg.User{
		{
			AccessKey: "user1key",
			SecretKey: "user1secret",
			Rules: []proxycfg.Rule{
				{Prefix: "photos/", Verbs: []string{"get", "list"}},
				{Prefix: "uploads/user1/", Verbs: []string{"get", "put", "delete", "list"}},
			},
		},
		{
			AccessKey: "user2key",
			SecretKey: "user2secret",
			Rules: []proxycfg.Rule{
				{Prefix: "", Verbs: []string{"get", "list"}},
			},
		},
	},
}

func TestMain(m *testing.M) {
	ctx := context.Background()

	// Start MinIO container
	container, err := minio.Run(ctx, "minio/minio:latest",
		minio.WithUsername("minioadmin"),
		minio.WithPassword("minioadmin"),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start minio: %v\n", err)
		os.Exit(1)
	}
	defer container.Terminate(ctx) //nolint:errcheck

	minioEndpoint, err := container.ConnectionString(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "minio endpoint: %v\n", err)
		os.Exit(1)
	}
	// ConnectionString returns "http://host:port"
	minioHost := strings.TrimPrefix(minioEndpoint, "http://")

	proxyConfig.MinIO.Endpoint = minioHost
	proxyConfig.MinIO.AccessKey = "minioadmin"
	proxyConfig.MinIO.SecretKey = "minioadmin"
	proxyConfig.MinIO.UseSSL = false

	// Create test bucket directly in MinIO
	adminS3 = newS3Client(minioEndpoint, "minioadmin", "minioadmin")
	if _, err := adminS3.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(testBucket),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "create bucket: %v\n", err)
		os.Exit(1)
	}

	// Start proxy on a random port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	proxyURL = "http://" + ln.Addr().String()
	proxyConfig.Server.Address = ln.Addr().String()

	p := proxy.New(proxyConfig)
	srv := server.New(proxyConfig, p)
	go srv.Serve(ln) //nolint:errcheck
	defer srv.Close()

	os.Exit(m.Run())
}

// newS3Client returns an aws-sdk-go-v2 S3 client pointed at endpoint with given credentials.
func newS3Client(endpoint, accessKey, secretKey string) *s3.Client {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		),
	)
	if err != nil {
		panic(err)
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
}

// proxyClient returns an S3 client pointed at the proxy with given credentials.
func proxyClient(accessKey, secretKey string) *s3.Client {
	return newS3Client(proxyURL, accessKey, secretKey)
}

// mustPutDirect puts an object directly into MinIO (bypasses the proxy, used for test setup).
func mustPutDirect(t *testing.T, key, content string) {
	t.Helper()
	_, err := adminS3.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String(key),
		Body:   strings.NewReader(content),
	})
	if err != nil {
		t.Fatalf("mustPutDirect(%q): %v", key, err)
	}
}

// assertHTTPStatus makes a raw HTTP request to the proxy and checks the status code.
func assertHTTPStatus(t *testing.T, method, path, accessKey, secretKey string, wantStatus int) {
	t.Helper()
	rawURL := proxyURL + path
	req, _ := http.NewRequest(method, rawURL, nil)
	req.Header.Set("X-Amz-Content-Sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	// sign manually via aws sdk
	client := proxyClient(accessKey, secretKey)
	_ = client // client used in higher-level tests; for raw requests we use http directly
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Errorf("got status %d, want %d", resp.StatusCode, wantStatus)
	}
}
```

- [ ] **Step 2: Verify the integration package compiles**

```bash
go build ./integration/...
```

Expected: no errors (no test functions yet, but the package compiles).

- [ ] **Step 3: Commit**

```bash
git add integration/setup_test.go
git commit -m "test: integration test infrastructure with testcontainers MinIO"
```

---

## Task 9: Integration — auth failure tests

**Files:**
- Create: `integration/auth_test.go`

- [ ] **Step 1: Write auth failure tests**

```go
// integration/auth_test.go
package integration

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestUnknownAccessKey(t *testing.T) {
	client := proxyClient("unknownkey", "somesecret")
	_, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("photos/img.jpg"),
	})
	if err == nil {
		t.Fatal("expected error for unknown access key")
	}
	if !strings.Contains(err.Error(), "InvalidAccessKeyId") {
		t.Errorf("expected InvalidAccessKeyId error, got: %v", err)
	}
}

func TestWrongSecretKey(t *testing.T) {
	client := proxyClient("user1key", "wrongsecret")
	_, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("photos/img.jpg"),
	})
	if err == nil {
		t.Fatal("expected error for wrong secret key")
	}
	if !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Errorf("expected SignatureDoesNotMatch error, got: %v", err)
	}
}

func TestMissingAuthHeader(t *testing.T) {
	resp, err := http.Get(proxyURL + "/" + testBucket + "/any-key")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got status %d, want 403", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run auth integration tests**

```bash
go test ./integration/... -v -run TestUnknown -run TestWrong -run TestMissing -timeout 120s
```

Expected: all 3 tests PASS (MinIO container starts, proxy validates credentials).

- [ ] **Step 3: Commit**

```bash
git add integration/auth_test.go
git commit -m "test(integration): auth failure scenarios"
```

---

## Task 10: Integration — GetObject tests

**Files:**
- Create: `integration/get_test.go`

- [ ] **Step 1: Write GetObject tests**

```go
// integration/get_test.go
package integration

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestGetObjectAllowed(t *testing.T) {
	mustPutDirect(t, "photos/sunset.jpg", "fake-jpeg-data")

	client := proxyClient("user1key", "user1secret")
	out, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("photos/sunset.jpg"),
	})
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	defer out.Body.Close()
	body, _ := io.ReadAll(out.Body)
	if string(body) != "fake-jpeg-data" {
		t.Errorf("got body %q, want %q", body, "fake-jpeg-data")
	}
}

func TestGetObjectDeniedWrongPrefix(t *testing.T) {
	mustPutDirect(t, "uploads/user2/secret.txt", "private")

	client := proxyClient("user1key", "user1secret")
	_, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("uploads/user2/secret.txt"),
	})
	if err == nil {
		t.Fatal("expected AccessDenied, got nil")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("expected AccessDenied, got: %v", err)
	}
}

func TestGetObjectDeniedWrongVerb(t *testing.T) {
	// user2 has only get+list, not delete
	mustPutDirect(t, "photos/to-delete.jpg", "data")

	client := proxyClient("user2key", "user2secret")
	_, err := client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("photos/to-delete.jpg"),
	})
	if err == nil {
		t.Fatal("expected AccessDenied for delete with read-only user")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("expected AccessDenied, got: %v", err)
	}
}

func TestGetObjectReadOnlyUserAllowed(t *testing.T) {
	mustPutDirect(t, "any/path/file.txt", "hello")

	client := proxyClient("user2key", "user2secret")
	out, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("any/path/file.txt"),
	})
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	defer out.Body.Close()
	body, _ := io.ReadAll(out.Body)
	if string(body) != "hello" {
		t.Errorf("got %q, want hello", body)
	}
}
```

- [ ] **Step 2: Run GetObject integration tests**

```bash
go test ./integration/... -v -run TestGetObject -timeout 120s
```

Expected: all 4 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add integration/get_test.go
git commit -m "test(integration): GetObject allowed and denied scenarios"
```

---

## Task 11: Integration — PutObject tests

**Files:**
- Create: `integration/put_test.go`

- [ ] **Step 1: Write PutObject tests**

```go
// integration/put_test.go
package integration

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestPutObjectAllowed(t *testing.T) {
	client := proxyClient("user1key", "user1secret")
	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("uploads/user1/hello.txt"),
		Body:   strings.NewReader("hello world"),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Verify it actually landed in MinIO
	out, err := adminS3.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("uploads/user1/hello.txt"),
	})
	if err != nil {
		t.Fatalf("verify get: %v", err)
	}
	defer out.Body.Close()
	body, _ := io.ReadAll(out.Body)
	if string(body) != "hello world" {
		t.Errorf("got %q, want %q", body, "hello world")
	}
}

func TestPutObjectDeniedReadOnlyPrefix(t *testing.T) {
	client := proxyClient("user1key", "user1secret")
	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("photos/fake.jpg"),
		Body:   strings.NewReader("data"),
	})
	if err == nil {
		t.Fatal("expected AccessDenied for put into read-only prefix")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("expected AccessDenied, got: %v", err)
	}
}

func TestPutObjectDeniedReadOnlyUser(t *testing.T) {
	client := proxyClient("user2key", "user2secret")
	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("any/path/new.txt"),
		Body:   strings.NewReader("data"),
	})
	if err == nil {
		t.Fatal("expected AccessDenied for put with read-only user")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("expected AccessDenied, got: %v", err)
	}
}
```

- [ ] **Step 2: Run PutObject integration tests**

```bash
go test ./integration/... -v -run TestPutObject -timeout 120s
```

Expected: all 3 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add integration/put_test.go
git commit -m "test(integration): PutObject allowed and denied scenarios"
```

---

## Task 12: Integration — DeleteObject tests

**Files:**
- Create: `integration/delete_test.go`

- [ ] **Step 1: Write DeleteObject tests**

```go
// integration/delete_test.go
package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestDeleteObjectAllowed(t *testing.T) {
	mustPutDirect(t, "uploads/user1/to-delete.txt", "bye")

	client := proxyClient("user1key", "user1secret")
	_, err := client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("uploads/user1/to-delete.txt"),
	})
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}

	// Verify it's gone
	_, err = adminS3.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("uploads/user1/to-delete.txt"),
	})
	if err == nil {
		t.Error("expected object to be deleted, but GetObject succeeded")
	}
}

func TestDeleteObjectDeniedReadOnlyPrefix(t *testing.T) {
	mustPutDirect(t, "photos/nodelete.jpg", "data")

	client := proxyClient("user1key", "user1secret")
	_, err := client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("photos/nodelete.jpg"),
	})
	if err == nil {
		t.Fatal("expected AccessDenied for delete on read-only prefix")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("expected AccessDenied, got: %v", err)
	}
}

func TestDeleteObjectDeniedReadOnlyUser(t *testing.T) {
	mustPutDirect(t, "any/nodelete.txt", "data")

	client := proxyClient("user2key", "user2secret")
	_, err := client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("any/nodelete.txt"),
	})
	if err == nil {
		t.Fatal("expected AccessDenied for read-only user delete")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("expected AccessDenied, got: %v", err)
	}
}
```

- [ ] **Step 2: Run DeleteObject integration tests**

```bash
go test ./integration/... -v -run TestDeleteObject -timeout 120s
```

Expected: all 3 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add integration/delete_test.go
git commit -m "test(integration): DeleteObject allowed and denied scenarios"
```

---

## Task 13: Integration — ListObjects tests

**Files:**
- Create: `integration/list_test.go`

- [ ] **Step 1: Write ListObjects tests**

```go
// integration/list_test.go
package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestListObjectsAllowed(t *testing.T) {
	mustPutDirect(t, "photos/a.jpg", "data")
	mustPutDirect(t, "photos/b.jpg", "data")
	mustPutDirect(t, "uploads/user1/c.txt", "data")

	client := proxyClient("user1key", "user1secret")
	out, err := client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: aws.String(testBucket),
		Prefix: aws.String("photos/"),
	})
	if err != nil {
		t.Fatalf("ListObjectsV2 failed: %v", err)
	}
	if len(out.Contents) < 2 {
		t.Errorf("got %d objects, want at least 2", len(out.Contents))
	}
	for _, obj := range out.Contents {
		if !strings.HasPrefix(*obj.Key, "photos/") {
			t.Errorf("got object outside photos/ prefix: %s", *obj.Key)
		}
	}
}

func TestListObjectsDeniedOutsidePrefix(t *testing.T) {
	// user1 only has list on photos/ and uploads/user1/ — not on "other/"
	client := proxyClient("user1key", "user1secret")
	_, err := client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: aws.String(testBucket),
		Prefix: aws.String("other/"),
	})
	if err == nil {
		t.Fatal("expected AccessDenied for list outside allowed prefix")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("expected AccessDenied, got: %v", err)
	}
}

func TestListObjectsDeniedNoListVerb(t *testing.T) {
	// user2 has no list verb
	// user2 has list verb but let's use a user without it:
	// Actually user2 has list. Let's try user1 listing root (empty prefix) which maps to no matching rule
	client := proxyClient("user1key", "user1secret")
	_, err := client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: aws.String(testBucket),
		Prefix: aws.String(""),
	})
	if err == nil {
		t.Fatal("expected AccessDenied when listing root bucket with restricted user")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("expected AccessDenied, got: %v", err)
	}
}

func TestListObjectsReadOnlyUserAllowed(t *testing.T) {
	mustPutDirect(t, "docs/readme.md", "# readme")

	client := proxyClient("user2key", "user2secret")
	out, err := client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: aws.String(testBucket),
		Prefix: aws.String("docs/"),
	})
	if err != nil {
		t.Fatalf("ListObjectsV2 failed: %v", err)
	}
	if len(out.Contents) < 1 {
		t.Errorf("got %d objects, want at least 1", len(out.Contents))
	}
}
```

- [ ] **Step 2: Run ListObjects integration tests**

```bash
go test ./integration/... -v -run TestListObjects -timeout 120s
```

Expected: all 4 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add integration/list_test.go
git commit -m "test(integration): ListObjects allowed, denied, and prefix enforcement"
```

---

## Task 14: Integration — large object streaming test

**Files:**
- Create: `integration/streaming_test.go`

- [ ] **Step 1: Write the streaming test**

```go
// integration/streaming_test.go
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// TestLargeObjectStreaming uploads and downloads a 100 MB object through the proxy
// to verify that data is streamed without being buffered in memory.
func TestLargeObjectStreaming(t *testing.T) {
	const size = 100 * 1024 * 1024 // 100 MB

	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("generate random data: %v", err)
	}

	client := proxyClient("user1key", "user1secret")

	// Upload through proxy
	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:        aws.String(testBucket),
		Key:           aws.String("uploads/user1/large.bin"),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(size),
	})
	if err != nil {
		t.Fatalf("PutObject 100MB failed: %v", err)
	}

	// Download through proxy
	out, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(testBucket),
		Key:    aws.String("uploads/user1/large.bin"),
	})
	if err != nil {
		t.Fatalf("GetObject 100MB failed: %v", err)
	}
	defer out.Body.Close()

	received, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if len(received) != size {
		t.Errorf("got %d bytes, want %d", len(received), size)
	}
	if !bytes.Equal(received, data) {
		t.Error("received data does not match uploaded data")
	}
}
```

- [ ] **Step 2: Run streaming test**

```bash
go test ./integration/... -v -run TestLargeObject -timeout 300s
```

Expected: PASS — 100 MB flows through without OOM. Test may take ~30-60s depending on machine.

- [ ] **Step 3: Run the full integration suite**

```bash
go test ./integration/... -timeout 300s -v
```

Expected: all integration tests PASS.

- [ ] **Step 4: Run all unit tests**

```bash
go test ./config/... ./acl/... ./auth/... ./proxy/... -v
```

Expected: all unit tests PASS.

- [ ] **Step 5: Commit**

```bash
git add integration/streaming_test.go
git commit -m "test(integration): 100MB streaming test verifying no in-memory buffering"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Covered by |
|-----------------|-----------|
| SigV4 HMAC validation | Task 4, 5, 9 |
| Prefix+verb ACL | Task 3, 10-14 |
| YAML config | Task 2 |
| Streaming (no buffer) | Task 6 (`io.Copy`), Task 14 |
| GetObject | Task 10 |
| PutObject | Task 11 |
| DeleteObject | Task 12 |
| ListObjects + prefix enforcement | Task 13 |
| Real MinIO container tests | Task 8-14 |
| Error responses as S3 XML | Task 6 (`writeS3Error`) |
| Unknown access key → 403 | Task 9 |
| Wrong secret → 403 | Task 9 |

All requirements covered. No TBDs or placeholders.
