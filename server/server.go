package server

import (
	"net/http"

	"gominioproxy/config"
)

func New(cfg *config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:    cfg.Server.Address,
		Handler: handler,
	}
}
