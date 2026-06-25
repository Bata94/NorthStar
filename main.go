// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

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
	"github.com/bata94/northstar/hooks"
	"github.com/bata94/northstar/log"
	"github.com/bata94/northstar/metrics"
	"github.com/bata94/northstar/resolver"
	"github.com/bata94/northstar/upstream"
)

var Version = "dev"

func main() {
	cfgPath := "./northstar.yaml"
	if v, ok := os.LookupEnv("NORTHSTAR_CONFIG"); ok && v != "" {
		cfgPath = v
	}

	cfg := config.Load()

	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if wErr := config.WriteEffectiveConfig(cfgPath, &cfg); wErr != nil {
			slog.Error("Failed to write default config", "error", wErr)
		} else {
			slog.Info("Generated default config file", "path", cfgPath, "mode", cfg.Mode)
		}
	}

	if cfg.TimeZone != "" {
		if loc, err := time.LoadLocation(cfg.TimeZone); err == nil {
			time.Local = loc
		} else {
			panic("invalid timezone: " + err.Error())
		}
	}

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
	slog.SetDefault(log.New(logLevel, logMode, cfg.LogDir, cfg.LogRetention))
	slog.Warn("starting northstar", "version", Version)

	var backend cache.Cache
	switch {
	case cfg.CacheAddr != "" && cfg.CacheFile != "":
		slog.Warn("Both CacheAddr and CacheFile set, using Valkey")
		fallthrough
	case cfg.CacheAddr != "":
		b, err := cache.NewValkey(cfg.CacheAddr, cfg.StaleAge)
		if err != nil {
			slog.Error("Valkey unreachable, using in-memory cache", "error", err)
			backend = cache.NewMemory(cfg.CacheMaxEntries)
		} else {
			slog.Info("Using Valkey cache", "addr", cfg.CacheAddr)
			backend = b
		}
	case cfg.CacheFile != "":
		b, err := cache.NewBbolt(cfg.CacheFile, cfg.StaleAge)
		if err != nil {
			slog.Error("Bbolt cache open failed, using in-memory cache", "error", err)
			backend = cache.NewMemory(cfg.CacheMaxEntries)
		} else {
			slog.Info("Using bbolt cache", "file", cfg.CacheFile)
			backend = b
		}
	default:
		backend = cache.NewMemory(cfg.CacheMaxEntries)
	}
	defer backend.Close()

	if cfg.CacheWarmup {
		warmupCtx, warmupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		go func() {
			defer warmupCancel()
			slog.Info("Starting cache warmup...")
			if err := backend.Warmup(warmupCtx, backend); err != nil {
				slog.Error("Cache warmup failed", "error", err)
			} else {
				slog.Info("Cache warmup completed")
			}
		}()
	}

	m := metrics.New()

	upstreamGroup, err := upstream.NewGroup(&cfg)
	if err != nil {
		slog.Error("Failed to initialize upstream group", "error", err)
		os.Exit(1)
	}
	defer upstreamGroup.Close()

	resolver.SetPipeline(buildPipeline(&cfg, backend, m))

	runtimeCfg := config.NewRuntimeConfig(&cfg)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)

	go func() {
		for range sighupCh {
			slog.Warn("SIGHUP received, reloading config...")
			reloadConfig(runtimeCfg, upstreamGroup, backend, m)
		}
	}()

	if cfg.MetricsEnable {
		metricsAddr := fmt.Sprintf(":%d", cfg.MetricsPort)
		go func() {
			if err := metrics.Serve(ctx, metricsAddr, m); err != nil {
				slog.Error("Metrics server error", "error", err)
			}
		}()
	}

	upstreamGroup.StartHealthChecks(ctx, m)
	upstreamGroup.StartSpeedAssessment(ctx)

	errCap := len(cfg.Listeners)
	if !cfg.TcpDisable {
		errCap *= 2
	}
	errChan := make(chan error, errCap)
	for _, l := range cfg.Listeners {
		l := l
		go func() {
			errChan <- resolver.Serve(ctx, l, upstreamGroup, backend, runtimeCfg, m)
		}()
		if !cfg.TcpDisable {
			go func() {
				errChan <- resolver.ServeTCP(ctx, l, upstreamGroup, backend, runtimeCfg, m, cfg.MaxTCPConnsPerClient)
			}()
		}
	}

	slog.Warn("Server listening", "listeners", cfg.Listeners, "tcp_disabled", cfg.TcpDisable, "metrics_enabled", cfg.MetricsEnable)

	select {
	case err := <-errChan:
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}
		cancel()
		slog.Warn("Initiating shutdown after error...")
		time.Sleep(time.Second)
	case <-ctx.Done():
		slog.Warn("Shutting down...")
	}

	slog.Warn("Goodbye.")
}

func buildPipeline(cfg *config.Config, c cache.Cache, m *metrics.Metrics) *hooks.Pipeline {
	p := hooks.NewPipeline()
	for _, h := range buildHooks(cfg, c, m) {
		p.Register(h)
	}
	return p
}

func reloadConfig(runtimeCfg *config.RuntimeConfig, upstreamGroup *upstream.Group, c cache.Cache, m *metrics.Metrics) {
	newCfg, err := config.Reload()
	if err != nil {
		slog.Error("Config reload failed", "error", err)
		return
	}
	runtimeCfg.ApplyConfig(&newCfg)
	if err := upstreamGroup.ReloadConfig(&newCfg); err != nil {
		slog.Error("Upstream reload failed", "error", err)
	}
	upstreamGroup.StartHealthChecks(context.Background(), m)
	upstreamGroup.StartSpeedAssessment(context.Background())
	if newLogLevel, ok := runtimeCfg.LogLevel.Load().(string); ok {
		newLogMode, _ := runtimeCfg.LogMode.Load().(string)
		if newLogMode == "" {
			newLogMode = newCfg.Mode
		}
		if newLogLevel == "" {
			switch newLogMode {
			case "dev":
				newLogLevel = "debug"
			default:
				newLogLevel = "warn"
			}
		}
		slog.SetDefault(log.New(newLogLevel, newLogMode, newCfg.LogDir, newCfg.LogRetention))
	}
	resolver.SetPipeline(buildPipeline(&newCfg, c, m))
	slog.Warn("Config reloaded")
}

func buildHooks(cfg *config.Config, c cache.Cache, m *metrics.Metrics) []hooks.Hook {
	var result []hooks.Hook

	rateCfg := cfg.Hooks.RateLimiting
	if rateCfg.Rate == 0 && cfg.RateLimit > 0 {
		rateCfg.Rate = cfg.RateLimit
	}
	result = append(result, hooks.NewRateLimitHook(
		rateCfg.Rate,
		rateCfg.Action,
		rateCfg.Priority,
		rateCfg.Enabled,
	))

	return result
}
