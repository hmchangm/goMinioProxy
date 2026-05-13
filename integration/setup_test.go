// integration/setup_test.go
package integration

import (
	"context"
	"fmt"
	"net"
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
