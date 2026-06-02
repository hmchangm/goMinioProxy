package server_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"gominioproxy/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunShutsDownGracefullyOnContextCancel(t *testing.T) {
	// Handler blocks until it receives the signal to proceed, simulating an in-flight request.
	handlerStarted := make(chan struct{})
	handlerCanProceed := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(handlerStarted)
		<-handlerCanProceed
		w.WriteHeader(http.StatusOK)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()

	srv := &http.Server{Handler: handler}
	ctx, cancel := context.WithCancel(context.Background())

	runDone := make(chan error, 1)
	go func() {
		runDone <- server.Run(ctx, srv, ln)
	}()

	// Start a slow in-flight request.
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		resp, err := http.Get("http://" + addr + "/")
		if err == nil {
			resp.Body.Close()
		}
	}()

	// Wait for the handler to be entered, then trigger shutdown.
	select {
	case <-handlerStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never started")
	}
	cancel()

	// Allow the in-flight handler to finish after shutdown is signalled.
	close(handlerCanProceed)

	// In-flight request must complete before Run returns.
	select {
	case <-reqDone:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not complete")
	}

	select {
	case err := <-runDone:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server.Run did not return after context cancel")
	}

	// New connections must be refused after shutdown.
	_, err = http.Get("http://" + addr + "/")
	assert.Error(t, err)
}

func TestRunReturnsErrorIfListenerFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	// Close the listener before Run — Serve will return immediately with an error.
	ln.Close()

	srv := &http.Server{Handler: http.NotFoundHandler()}
	ctx := context.Background()

	err = server.Run(ctx, srv, ln)
	assert.Error(t, err)
}
