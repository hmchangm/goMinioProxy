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

func TestListObjectsDeniedRootBucketListing(t *testing.T) {
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
