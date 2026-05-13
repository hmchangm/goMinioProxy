package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server ServerConfig `yaml:"server"`
	MinIO  MinIOConfig  `yaml:"minio"`
	Users  []User       `yaml:"users"`
}

type ServerConfig struct {
	Address string `yaml:"address"`
}

type MinIOConfig struct {
	Endpoint  string `yaml:"endpoint"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Bucket    string `yaml:"bucket"`
	UseSSL    bool   `yaml:"use_ssl"`
	Region    string `yaml:"region"`
}

type User struct {
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Rules     []Rule `yaml:"rules"`
}

type Rule struct {
	Prefix string   `yaml:"prefix"`
	Verbs  []string `yaml:"verbs"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.MinIO.Bucket == "" {
		return nil, fmt.Errorf("minio.bucket is required")
	}
	if cfg.MinIO.Endpoint == "" {
		return nil, fmt.Errorf("minio.endpoint is required")
	}
	return &cfg, nil
}
