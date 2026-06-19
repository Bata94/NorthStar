// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package config

import (
	"os"
	"testing"
)

func clearEnv() {
	for _, key := range []string{
		"NORTHSTAR_MODE",
		"NORTHSTAR_DNS_PORT",
		"NORTHSTAR_UPSTREAM",
		"NORTHSTAR_CACHE_ADDR",
		"NORTHSTAR_DNS_IPV4_DISABLE",
		"NORTHSTAR_DNS_IPV6_DISABLE",
		"NORTHSTAR_TCP_DISABLE",
		"NORTHSTAR_DNS_RATE_LIMIT",
		"NORTHSTAR_DNS_STALE_AGE",
		"NORTHSTAR_UPSTREAM_POOL_SIZE",
		"NORTHSTAR_UPSTREAM_POOL_IDLE",
		"NORTHSTAR_LOG_LEVEL",
		"NORTHSTAR_LOG_MODE",
		"NORTHSTAR_LOG_DIR",
		"NORTHSTAR_LOG_RETENTION",
		"NORTHSTAR_TZ",
		"NORTHSTAR_METRICS_ENABLE",
		"NORTHSTAR_METRICS_PORT",
		"NORTHSTAR_CONFIG",
	} {
		_ = os.Unsetenv(key)
	}
}

func TestDefaults(t *testing.T) {
	clearEnv()
	cfg := Load()

	if cfg.Mode != "prod" {
		t.Errorf("Mode = %s, want prod", cfg.Mode)
	}
	if cfg.DNSPort != 53 {
		t.Errorf("DNSPort = %d, want 53", cfg.DNSPort)
	}
	if cfg.UpstreamAddr != "8.8.8.8:53" {
		t.Errorf("UpstreamAddr = %s, want 8.8.8.8:53", cfg.UpstreamAddr)
	}
	if cfg.CacheAddr != "" {
		t.Errorf("CacheAddr = %s, want empty", cfg.CacheAddr)
	}
	if cfg.TcpDisable {
		t.Error("TcpDisable should be false")
	}
	if cfg.RateLimit != 0 {
		t.Errorf("RateLimit = %d, want 0", cfg.RateLimit)
	}
	if cfg.StaleAge != 60 {
		t.Errorf("StaleAge = %d, want 60", cfg.StaleAge)
	}
	if cfg.UpstreamPoolSize != 10 {
		t.Errorf("UpstreamPoolSize = %d, want 10", cfg.UpstreamPoolSize)
	}
	if cfg.UpstreamPoolIdle != 30 {
		t.Errorf("UpstreamPoolIdle = %d, want 30", cfg.UpstreamPoolIdle)
	}
	if cfg.Ipv4Disable || cfg.Ipv6Disable {
		t.Error("default: both v4 and v6 should be enabled")
	}
	if len(cfg.Listeners) != 1 {
		t.Fatalf("expected 1 listener (dual-stack), got %d", len(cfg.Listeners))
	}
	if cfg.Listeners[0].IP != "::" {
		t.Errorf("listener IP = %s, want ::", cfg.Listeners[0].IP)
	}
	if cfg.Listeners[0].Port != 53 {
		t.Errorf("listener Port = %d, want 53", cfg.Listeners[0].Port)
	}
	if cfg.MetricsEnable {
		t.Error("MetricsEnable should be false by default")
	}
	if cfg.MetricsPort != 9153 {
		t.Errorf("MetricsPort = %d, want 9153", cfg.MetricsPort)
	}
	if cfg.LogDir != "." {
		t.Errorf("LogDir = %s, want .", cfg.LogDir)
	}
	if cfg.LogRetention != 7 {
		t.Errorf("LogRetention = %d, want 7", cfg.LogRetention)
	}
	if cfg.TimeZone != "" {
		t.Errorf("TimeZone = %s, want empty", cfg.TimeZone)
	}
}

func TestMetricsConfig(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_METRICS_ENABLE", "true")
	_ = os.Setenv("NORTHSTAR_METRICS_PORT", "9090")
	defer clearEnv()

	cfg := Load()
	if !cfg.MetricsEnable {
		t.Error("MetricsEnable should be true")
	}
	if cfg.MetricsPort != 9090 {
		t.Errorf("MetricsPort = %d, want 9090", cfg.MetricsPort)
	}
}

func TestCustomPortAndUpstream(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_DNS_PORT", "8053")
	_ = os.Setenv("NORTHSTAR_UPSTREAM", "1.1.1.1:53")
	defer clearEnv()

	cfg := Load()

	if cfg.DNSPort != 8053 {
		t.Errorf("DNSPort = %d, want 8053", cfg.DNSPort)
	}
	if cfg.UpstreamAddr != "1.1.1.1:53" {
		t.Errorf("UpstreamAddr = %s, want 1.1.1.1:53", cfg.UpstreamAddr)
	}
}

func TestIpv4Only(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_DNS_IPV6_DISABLE", "true")
	defer clearEnv()

	cfg := Load()
	if cfg.Ipv4Disable {
		t.Error("Ipv4Disable should be false")
	}
	if !cfg.Ipv6Disable {
		t.Error("Ipv6Disable should be true")
	}
	if len(cfg.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(cfg.Listeners))
	}
	if cfg.Listeners[0].IP != "0.0.0.0" {
		t.Errorf("listener IP = %s, want 0.0.0.0", cfg.Listeners[0].IP)
	}
}

func TestIpv6Only(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_DNS_IPV4_DISABLE", "true")
	defer clearEnv()

	cfg := Load()
	if !cfg.Ipv4Disable {
		t.Error("Ipv4Disable should be true")
	}
	if cfg.Ipv6Disable {
		t.Error("Ipv6Disable should be false")
	}
	if len(cfg.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(cfg.Listeners))
	}
	if cfg.Listeners[0].IP != "::" {
		t.Errorf("listener IP = %s, want ::", cfg.Listeners[0].IP)
	}
}

func TestBothDisabledPanics(t *testing.T) {
	clearEnv()
	defer clearEnv()
	_ = os.Setenv("NORTHSTAR_DNS_IPV4_DISABLE", "true")
	_ = os.Setenv("NORTHSTAR_DNS_IPV6_DISABLE", "true")

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when both v4 and v6 are disabled")
		}
	}()
	Load()
}

func TestTcpDisable(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_TCP_DISABLE", "true")
	defer clearEnv()

	cfg := Load()
	if !cfg.TcpDisable {
		t.Error("TcpDisable should be true")
	}
}

func TestRateLimit(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_DNS_RATE_LIMIT", "100")
	defer clearEnv()

	cfg := Load()
	if cfg.RateLimit != 100 {
		t.Errorf("RateLimit = %d, want 100", cfg.RateLimit)
	}
}

func TestStaleAge(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_DNS_STALE_AGE", "30")
	defer clearEnv()

	cfg := Load()
	if cfg.StaleAge != 30 {
		t.Errorf("StaleAge = %d, want 30", cfg.StaleAge)
	}
}

func TestPoolConfig(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_UPSTREAM_POOL_SIZE", "20")
	_ = os.Setenv("NORTHSTAR_UPSTREAM_POOL_IDLE", "60")
	defer clearEnv()

	cfg := Load()
	if cfg.UpstreamPoolSize != 20 {
		t.Errorf("UpstreamPoolSize = %d, want 20", cfg.UpstreamPoolSize)
	}
	if cfg.UpstreamPoolIdle != 60 {
		t.Errorf("UpstreamPoolIdle = %d, want 60", cfg.UpstreamPoolIdle)
	}
}

func TestCacheAddr(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_CACHE_ADDR", "localhost:6379")
	defer clearEnv()

	cfg := Load()
	if cfg.CacheAddr != "localhost:6379" {
		t.Errorf("CacheAddr = %s, want localhost:6379", cfg.CacheAddr)
	}
}

func TestMode(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_MODE", "dev")
	defer clearEnv()

	cfg := Load()
	if cfg.Mode != "dev" {
		t.Errorf("Mode = %s, want dev", cfg.Mode)
	}
}

func TestTimeZone(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_TZ", "Europe/Berlin")
	defer clearEnv()

	cfg := Load()
	if cfg.TimeZone != "Europe/Berlin" {
		t.Errorf("TimeZone = %s, want Europe/Berlin", cfg.TimeZone)
	}
}

func TestLogConfig(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_LOG_LEVEL", "debug")
	_ = os.Setenv("NORTHSTAR_LOG_MODE", "dev")
	_ = os.Setenv("NORTHSTAR_LOG_DIR", "/var/log/northstar")
	_ = os.Setenv("NORTHSTAR_LOG_RETENTION", "30")
	defer clearEnv()

	cfg := Load()
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %s, want debug", cfg.LogLevel)
	}
	if cfg.LogMode != "dev" {
		t.Errorf("LogMode = %s, want dev", cfg.LogMode)
	}
	if cfg.LogDir != "/var/log/northstar" {
		t.Errorf("LogDir = %s, want /var/log/northstar", cfg.LogDir)
	}
	if cfg.LogRetention != 30 {
		t.Errorf("LogRetention = %d, want 30", cfg.LogRetention)
	}
}

func TestEnvVarPrecedence(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_MODE", "prod")
	_ = os.Setenv("NORTHSTAR_DNS_PORT", "8053")
	defer clearEnv()

	cfg := Load()
	if cfg.Mode != "prod" {
		t.Errorf("Mode = %s, want prod", cfg.Mode)
	}
	if cfg.DNSPort != 8053 {
		t.Errorf("DNSPort = %d, want 8053", cfg.DNSPort)
	}
}

func TestLoadFromFile(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	cfgPath := dir + "/test.yaml"
	if err := WriteDefaultConfig(cfgPath); err != nil {
		t.Fatal(err)
	}
	_ = os.Setenv("NORTHSTAR_CONFIG", cfgPath)
	defer clearEnv()

	cfg := Load()
	if cfg.Mode != "prod" {
		t.Errorf("Mode = %s, want prod", cfg.Mode)
	}
	if cfg.ConfigPath != cfgPath {
		t.Errorf("ConfigPath = %s, want %s", cfg.ConfigPath, cfgPath)
	}
}

func TestFileEnvOverride(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	cfgPath := dir + "/test.yaml"
	if err := WriteDefaultConfig(cfgPath); err != nil {
		t.Fatal(err)
	}
	_ = os.Setenv("NORTHSTAR_CONFIG", cfgPath)
	_ = os.Setenv("NORTHSTAR_DNS_PORT", "8053")
	_ = os.Setenv("NORTHSTAR_UPSTREAM", "1.1.1.1:53")
	defer clearEnv()

	cfg := Load()
	if cfg.DNSPort != 8053 {
		t.Errorf("DNSPort = %d, want 8053 (env should override file)", cfg.DNSPort)
	}
	if cfg.UpstreamAddr != "1.1.1.1:53" {
		t.Errorf("UpstreamAddr = %s, want 1.1.1.1:53", cfg.UpstreamAddr)
	}
}

func TestWriteDefaultConfigRoundTrip(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	cfgPath := dir + "/test.yaml"
	if err := WriteDefaultConfig(cfgPath); err != nil {
		t.Fatal(err)
	}

	_ = os.Setenv("NORTHSTAR_CONFIG", cfgPath)
	defer clearEnv()

	cfg := Load()
	if cfg.Mode != "prod" {
		t.Errorf("Mode = %s, want prod", cfg.Mode)
	}
	if cfg.DNSPort != 53 {
		t.Errorf("DNSPort = %d, want 53", cfg.DNSPort)
	}
	if cfg.UpstreamAddr != "8.8.8.8:53" {
		t.Errorf("UpstreamAddr = %s, want 8.8.8.8:53", cfg.UpstreamAddr)
	}
	if cfg.RateLimit != 0 {
		t.Errorf("RateLimit = %d, want 0", cfg.RateLimit)
	}
	if cfg.StaleAge != 60 {
		t.Errorf("StaleAge = %d, want 60", cfg.StaleAge)
	}
	if cfg.Hooks.RateLimiting.Priority != 100 {
		t.Errorf("Hook priority = %d, want 100", cfg.Hooks.RateLimiting.Priority)
	}
}

func TestFileOverridesDefaults(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	cfgPath := dir + "/test.yaml"
	_ = os.Setenv("NORTHSTAR_CONFIG", cfgPath)
	defer clearEnv()

	yamlContent := `
mode: dev
dns_port: 8053
upstream: 9.9.9.9:53
rate_limit: 50
stale_age: 120
upstream_pool_size: 20
upstream_pool_idle: 60
log_level: debug
log_mode: dev
metrics_enable: true
hooks:
  rate_limiting:
    enabled: true
    priority: 200
    rate: 100
    action: drop
`
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Load()
	if cfg.Mode != "dev" {
		t.Errorf("Mode = %s, want dev", cfg.Mode)
	}
	if cfg.DNSPort != 8053 {
		t.Errorf("DNSPort = %d, want 8053", cfg.DNSPort)
	}
	if cfg.UpstreamAddr != "9.9.9.9:53" {
		t.Errorf("UpstreamAddr = %s, want 9.9.9.9:53", cfg.UpstreamAddr)
	}
	if cfg.RateLimit != 50 {
		t.Errorf("RateLimit = %d, want 50", cfg.RateLimit)
	}
	if cfg.StaleAge != 120 {
		t.Errorf("StaleAge = %d, want 120", cfg.StaleAge)
	}
	if !cfg.MetricsEnable {
		t.Error("MetricsEnable should be true")
	}
	if !cfg.Hooks.RateLimiting.Enabled {
		t.Error("Hook should be enabled")
	}
	if cfg.Hooks.RateLimiting.Priority != 200 {
		t.Errorf("Hook priority = %d, want 200", cfg.Hooks.RateLimiting.Priority)
	}
	if cfg.Hooks.RateLimiting.Action != "drop" {
		t.Errorf("Hook action = %s, want drop", cfg.Hooks.RateLimiting.Action)
	}
}

func TestFileEnvHierarchy(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	cfgPath := dir + "/test.yaml"
	_ = os.Setenv("NORTHSTAR_CONFIG", cfgPath)
	defer clearEnv()

	yamlContent := `
dns_port: 8053
upstream: 9.9.9.9:53
log_level: debug
`
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	_ = os.Setenv("NORTHSTAR_DNS_PORT", "9053")
	_ = os.Setenv("NORTHSTAR_UPSTREAM", "1.1.1.1:53")

	cfg := Load()
	// Env overrides file
	if cfg.DNSPort != 9053 {
		t.Errorf("DNSPort = %d, want 9053 (env > file)", cfg.DNSPort)
	}
	if cfg.UpstreamAddr != "1.1.1.1:53" {
		t.Errorf("UpstreamAddr = %s, want 1.1.1.1:53 (env > file)", cfg.UpstreamAddr)
	}
	// File value used when env not set
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %s, want debug (file > default)", cfg.LogLevel)
	}
	// Default used when neither file nor env set
	if cfg.StaleAge != 60 {
		t.Errorf("StaleAge = %d, want 60 (default)", cfg.StaleAge)
	}
}

func TestReload(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	cfgPath := dir + "/test.yaml"
	_ = os.Setenv("NORTHSTAR_CONFIG", cfgPath)
	defer clearEnv()

	yamlContent := `rate_limit: 50
stale_age: 120
`
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Reload()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RateLimit != 50 {
		t.Errorf("RateLimit = %d, want 50", cfg.RateLimit)
	}
	if cfg.StaleAge != 120 {
		t.Errorf("StaleAge = %d, want 120", cfg.StaleAge)
	}
}

func TestWriteEffectiveConfig(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	cfgPath := dir + "/test.yaml"
	_ = os.Setenv("NORTHSTAR_CONFIG", cfgPath)
	_ = os.Setenv("NORTHSTAR_MODE", "dev")
	_ = os.Setenv("NORTHSTAR_DNS_PORT", "8053")
	defer clearEnv()

	cfg := Load()

	if err := WriteEffectiveConfig(cfgPath, &cfg); err != nil {
		t.Fatal(err)
	}

	clearEnv()
	_ = os.Setenv("NORTHSTAR_CONFIG", cfgPath)

	loaded := Load()
	if loaded.Mode != "dev" {
		t.Errorf("Mode = %s, want dev (file contains effective value)", loaded.Mode)
	}
	if loaded.DNSPort != 8053 {
		t.Errorf("DNSPort = %d, want 8053 (file contains effective value)", loaded.DNSPort)
	}
}
