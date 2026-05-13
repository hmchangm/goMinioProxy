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
