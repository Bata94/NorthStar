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

	"github.com/bata94/northstar/acl"
	"github.com/bata94/northstar/api"
	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/hooks"
	"github.com/bata94/northstar/log"
	"github.com/bata94/northstar/metrics"
	"github.com/bata94/northstar/resolver"
	"github.com/bata94/northstar/tls"
	"github.com/bata94/northstar/upstream"
	"github.com/bata94/northstar/zone"
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

	zoneList, err := parseZones(&cfg)
	if err != nil {
		slog.Error("Failed to parse zones", "error", err)
		os.Exit(1)
	}
	authHook := hooks.NewAuthoritativeHook(zoneList)

	aclRuleset, err := acl.NewRuleSet(cfg.ACLs)
	if err != nil {
		slog.Error("Failed to parse ACLs", "error", err)
		os.Exit(1)
	}
	aclHook := hooks.NewAclHook(aclRuleset)

	blockingHook, _ := buildHooksWithBlocking(&cfg, backend, m, authHook, aclHook)
	resolver.SetPipeline(buildPipeline(&cfg, backend, m, authHook, aclHook))

	runtimeCfg := config.NewRuntimeConfig(&cfg)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)

	go func() {
		for range sighupCh {
			slog.Warn("SIGHUP received, reloading config...")
			reloadConfig(runtimeCfg, upstreamGroup, backend, m, authHook, aclHook)
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

	if cfg.APIEnable {
		apiSrv := api.New(&cfg, cfgPath, upstreamGroup, backend, m, blockingHook, authHook, aclHook)
		go func() {
			if err := apiSrv.Serve(ctx); err != nil {
				slog.Error("API server error", "error", err)
			}
		}()
	}

	upstreamGroup.StartHealthChecks(ctx, m)
	upstreamGroup.StartSpeedAssessment(ctx)

	if cfg.DoTEnabled || cfg.DoHEnabled || cfg.DoQEnabled {
		tlsCfg, err := tls.ServerConfig(cfg.TLS)
		if err != nil {
			slog.Error("Failed to create TLS config for encrypted DNS", "error", err)
		} else {
			if cfg.DoHEnabled {
				dohAddr := fmt.Sprintf(":%d", cfg.DoHPort)
				go func() {
					if err := resolver.ServeDOH(ctx, dohAddr, tlsCfg, upstreamGroup, backend, runtimeCfg, m); err != nil {
						slog.Error("DoH server error", "error", err)
					}
				}()
				slog.Warn("DoH server starting", "addr", dohAddr)
			}
			if cfg.DoTEnabled {
				dotAddr := fmt.Sprintf(":%d", cfg.DoTPort)
				go func() {
					if err := resolver.ServeDOT(ctx, dotAddr, tlsCfg, upstreamGroup, backend, runtimeCfg, m); err != nil {
						slog.Error("DoT server error", "error", err)
					}
				}()
				slog.Warn("DoT server starting", "addr", dotAddr)
			}
			if cfg.DoQEnabled {
				doqAddr := fmt.Sprintf(":%d", cfg.DoQPort)
				go func() {
					if err := resolver.ServeDOQ(ctx, doqAddr, tlsCfg, upstreamGroup, backend, runtimeCfg, m); err != nil {
						slog.Error("DoQ server error", "error", err)
					}
				}()
				slog.Warn("DoQ server starting", "addr", doqAddr)
			}
		}
	}

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

func buildPipeline(cfg *config.Config, c cache.Cache, m *metrics.Metrics, authHook *hooks.AuthoritativeHook, aclHook *hooks.AclHook) *hooks.Pipeline {
	p := hooks.NewPipeline()
	_, hks := buildHooksWithBlocking(cfg, c, m, authHook, aclHook)
	for _, h := range hks {
		p.Register(h)
	}
	return p
}

func reloadConfig(runtimeCfg *config.RuntimeConfig, upstreamGroup *upstream.Group, c cache.Cache, m *metrics.Metrics, authHook *hooks.AuthoritativeHook, aclHook *hooks.AclHook) {
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
	if newZones, err := parseZones(&newCfg); err == nil {
		authHook.ReplaceZones(newZones)
	} else {
		slog.Error("Zone reload failed", "error", err)
	}
	if newACLs, err := acl.NewRuleSet(newCfg.ACLs); err == nil {
		aclHook.ReplaceRules(newACLs)
	} else {
		slog.Error("ACL reload failed", "error", err)
	}
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
	resolver.SetPipeline(buildPipeline(&newCfg, c, m, authHook, aclHook))
	slog.Warn("Config reloaded")
}

func buildHooksWithBlocking(cfg *config.Config, c cache.Cache, m *metrics.Metrics, authHook *hooks.AuthoritativeHook, aclHook *hooks.AclHook) (*hooks.BlockingHook, []hooks.Hook) {
	var result []hooks.Hook
	var blockHook *hooks.BlockingHook

	if authHook != nil && authHook.Enabled() {
		result = append(result, authHook)
	}
	if aclHook != nil && aclHook.Enabled() {
		result = append(result, aclHook)
	}

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

	blockCfg := cfg.Hooks.Blocking
	if blockCfg.Enabled {
		rpzConfigs := make([]struct{ Path, Action string }, len(blockCfg.RPZ))
		for i, r := range blockCfg.RPZ {
			rpzConfigs[i] = struct{ Path, Action string }{r.Path, r.Action}
		}
		hook, err := hooks.NewBlockingHook(struct {
			Enabled      bool
			Priority     int
			BlockAction  string
			SinkholeAddr string
			Blocklists   []string
			Allowlists   []string
			DomainRPS    int
			RPZ          []struct{ Path, Action string }
		}{
			Enabled:      blockCfg.Enabled,
			Priority:     blockCfg.Priority,
			BlockAction:  blockCfg.BlockAction,
			SinkholeAddr: blockCfg.SinkholeAddr,
			Blocklists:   blockCfg.Blocklists,
			Allowlists:   blockCfg.Allowlists,
			DomainRPS:    blockCfg.DomainRPS,
			RPZ:          rpzConfigs,
		}, m)
		if err != nil {
			slog.Error("Failed to create blocking hook", "error", err)
		} else {
			slog.Info("Blocking hook created", "blocklists", blockCfg.Blocklists, "allowlists", blockCfg.Allowlists, "action", blockCfg.BlockAction)
			result = append(result, hook)
			blockHook = hook
		}
	}

	qminCfg := cfg.Hooks.QMinimizer
	if qminCfg.Enabled {
		pre, post := hooks.NewQMinimizerHooks(true, qminCfg.Priority, qminCfg.Priority+1, qminCfg.KeepLabels)
		result = append(result, pre, post)
		slog.Info("QNAME minimization enabled", "keep_labels", qminCfg.KeepLabels)
	}

	anyQueryCfg := cfg.Hooks.AnyQuery
	result = append(result, hooks.NewAnyQueryHook(
		anyQueryCfg.Enabled,
		anyQueryCfg.Priority,
		anyQueryCfg.Action,
	))

	dns64Cfg := cfg.Hooks.Dns64
	if dns64Cfg.Enabled && dns64Cfg.Prefix != "" {
		result = append(result, hooks.NewDns64Hook(
			dns64Cfg.Enabled,
			dns64Cfg.Priority,
			dns64Cfg.Prefix,
		))
		slog.Info("DNS64 enabled", "prefix", dns64Cfg.Prefix)
	}

	ecsCfg := cfg.Hooks.ECS
	if ecsCfg.Enabled {
		result = append(result, hooks.NewEcsHook(
			ecsCfg.Enabled,
			ecsCfg.Priority,
			ecsCfg.PrefixV4,
			ecsCfg.PrefixV6,
		))
		slog.Info("ECS enabled", "prefix_v4", ecsCfg.PrefixV4, "prefix_v6", ecsCfg.PrefixV6)
	}

	dnssecCfg := cfg.Hooks.Dnssec
	if dnssecCfg.Enabled {
		result = append(result, hooks.NewDnssecHook(
			dnssecCfg.Enabled,
			dnssecCfg.Priority,
			dnssecCfg.Validation,
			dnssecCfg.TrustAnchor,
		))
		slog.Info("DNSSEC validation enabled", "mode", dnssecCfg.Validation)
	}

	return blockHook, result
}

func parseZones(cfg *config.Config) ([]*zone.Zone, error) {
	var zones []*zone.Zone
	for _, zc := range cfg.Zones {
		z, err := zone.ParseZoneConfig(zc)
		if err != nil {
			return nil, err
		}
		zones = append(zones, z)
	}
	return zones, nil
}
