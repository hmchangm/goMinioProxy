package main

import (
	"log"
	"os"

	"gominioproxy/config"
	"gominioproxy/proxy"
	"gominioproxy/server"
)

func main() {
	cfgPath := "config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	p := proxy.New(cfg)
	srv := server.New(cfg, p)

	log.Printf("proxy listening on %s → minio %s/%s", cfg.Server.Address, cfg.MinIO.Endpoint, cfg.MinIO.Bucket)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
