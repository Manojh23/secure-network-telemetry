package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Manojh23/secure-network-telemetry/internal/gateway"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func run() error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	keyPath := os.Getenv("KEY_FILE")
	if keyPath == "" {
		keyPath = ".local/keys.json"
	}
	b, e := os.ReadFile(keyPath)
	if e != nil {
		return e
	}
	keys := map[string]gateway.Credential{}
	if e = json.Unmarshal(b, &keys); e != nil {
		return e
	}
	data := os.Getenv("DATA_FILE")
	if data == "" {
		data = ".local/reports.jsonl"
	}
	if e = os.MkdirAll(filepath.Dir(data), 0700); e != nil {
		return e
	}
	store, e := gateway.Open(data, 10000)
	if e != nil {
		return e
	}
	defer store.Close()
	api, e := gateway.New(store, keys, 32, log)
	if e != nil {
		return e
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9443"
	}
	cert, key := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY")
	if cert == "" {
		cert = ".local/server.crt"
	}
	if key == "" {
		key = ".local/server.key"
	}
	server := &http.Server{Addr: addr, Handler: api, TLSConfig: gateway.TLSConfig(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS(cert, key) }()
	log.Info("listening", "address", addr, "minimum_tls", "1.3")
	select {
	case e = <-done:
		return e
	case <-ctx.Done():
		drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e = server.Shutdown(drain); e != nil {
			return e
		}
		e = <-done
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	}
}
func main() {
	if e := run(); e != nil {
		slog.Error("gateway stopped", "error", e)
		os.Exit(1)
	}
}
