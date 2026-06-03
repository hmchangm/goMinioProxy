package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"gominioproxy/config"
	"gominioproxy/metrics"
	"gominioproxy/proxy"
	"gominioproxy/server"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

	reg := prometheus.NewRegistry()
	rec := metrics.NewPrometheusRecorder(reg)

	p := proxy.New(cfg, proxy.WithRecorder(rec))

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.Handle("/", p)

	srv := server.New(cfg, mux)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Printf("proxy listening on %s → minio %s/%s", cfg.Server.Address, cfg.MinIO.Endpoint, cfg.MinIO.Bucket)
	if err := server.Run(ctx, srv, ln); err != nil {
		log.Fatalf("server: %v", err)
	}
	log.Println("shutdown complete")
}
