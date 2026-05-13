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
