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

func TestLargeObjectStreaming(t *testing.T) {
	const size = 100 * 1024 * 1024 // 100 MB

	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("generate random data: %v", err)
	}

	client := proxyClient("user1key", "user1secret")

	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:        aws.String(testBucket),
		Key:           aws.String("uploads/user1/large.bin"),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(size),
	})
	if err != nil {
		t.Fatalf("PutObject 100MB failed: %v", err)
	}

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
