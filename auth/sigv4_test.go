// auth/sigv4_test.go
package auth_test

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
