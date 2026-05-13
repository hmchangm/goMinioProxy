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
