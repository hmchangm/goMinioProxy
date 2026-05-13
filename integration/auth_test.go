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
