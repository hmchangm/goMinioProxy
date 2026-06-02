package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

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

	ln, err := net.Listen("tcp", cfg.Server.Address)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	p := proxy.New(cfg)
	srv := server.New(cfg, p)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Printf("proxy listening on %s → minio %s/%s", cfg.Server.Address, cfg.MinIO.Endpoint, cfg.MinIO.Bucket)
	if err := server.Run(ctx, srv, ln); err != nil {
		log.Fatalf("server: %v", err)
	}
	log.Println("shutdown complete")
}
