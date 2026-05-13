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
