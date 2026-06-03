// proxy/proxy_test.go
package proxy

import (
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
