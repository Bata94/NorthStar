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
		"NORTHSTAR_METRICS_ENABLE",
		"NORTHSTAR_METRICS_PORT",
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

func TestLogConfig(t *testing.T) {
	clearEnv()
	_ = os.Setenv("NORTHSTAR_LOG_LEVEL", "debug")
	_ = os.Setenv("NORTHSTAR_LOG_MODE", "dev")
	defer clearEnv()

	cfg := Load()
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %s, want debug", cfg.LogLevel)
	}
	if cfg.LogMode != "dev" {
		t.Errorf("LogMode = %s, want dev", cfg.LogMode)
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
