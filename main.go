package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/log"
	"github.com/bata94/northstar/metrics"
	"github.com/bata94/northstar/resolver"
)

func main() {
	cfg := config.Load()

	logMode := cfg.LogMode
	if logMode == "" {
		logMode = cfg.Mode
	}
	logLevel := cfg.LogLevel
	if logLevel == "" {
		switch logMode {
		case "dev":
			logLevel = "debug"
		default:
			logLevel = "warn"
		}
	}
	slog.SetDefault(log.New(logLevel, logMode))

	var backend cache.Cache
	if cfg.CacheAddr != "" {
		b, err := cache.NewValkey(cfg.CacheAddr, cfg.StaleAge)
		if err != nil {
			slog.Warn("Valkey unreachable, using in-memory cache", "error", err)
			backend = cache.NewMemory()
		} else {
			slog.Info("Using Valkey cache", "addr", cfg.CacheAddr)
			backend = b
		}
	} else {
		backend = cache.NewMemory()
	}
	defer func() {
		if err := backend.Close(); err != nil {
			slog.Error("Error closing cache backend", "error", err)
		}
	}()

	m := metrics.New()

	poolIdle := time.Duration(cfg.UpstreamPoolIdle) * time.Second
	udpPool := resolver.NewPool(cfg.UpstreamAddr, "udp", cfg.UpstreamPoolSize, poolIdle)
	defer udpPool.Close()

	var tcpPool *resolver.Pool
	if !cfg.TcpDisable {
		tcpPool = resolver.NewPool(cfg.UpstreamAddr, "tcp", cfg.UpstreamPoolSize, poolIdle)
		defer tcpPool.Close()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if cfg.MetricsEnable {
		metricsAddr := fmt.Sprintf(":%d", cfg.MetricsPort)
		go func() {
			if err := metrics.Serve(ctx, metricsAddr, m); err != nil {
				slog.Error("Metrics server error", "error", err)
			}
		}()
	}

	errCap := len(cfg.Listeners)
	if !cfg.TcpDisable {
		errCap *= 2
	}
	errChan := make(chan error, errCap)
	for _, l := range cfg.Listeners {
		l := l
		go func() {
			errChan <- resolver.Serve(ctx, l, cfg.UpstreamAddr, backend, cfg.RateLimit, cfg.StaleAge, udpPool, m)
		}()
		if !cfg.TcpDisable {
			go func() {
				errChan <- resolver.ServeTCP(ctx, l, cfg.UpstreamAddr, backend, cfg.RateLimit, cfg.StaleAge, tcpPool, m)
			}()
		}
	}

	slog.Info("Server listening", "listeners", cfg.Listeners, "tcp_disabled", cfg.TcpDisable, "metrics_enabled", cfg.MetricsEnable)

	select {
	case err := <-errChan:
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}
		cancel()
		slog.Info("Initiating shutdown after error...")
		time.Sleep(time.Second)
	case <-ctx.Done():
		slog.Info("Shutting down...")
	}

	slog.Info("Goodbye.")
}
