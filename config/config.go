// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Listener struct {
	IP   string
	Port int
}

type RateLimitHookConfig struct {
	Enabled  bool
	Priority int
	Rate     int
	Action   string
}

type HookConfig struct {
	RateLimiting RateLimitHookConfig
}

type Config struct {
	Mode             string
	DNSPort          int
	UpstreamAddr     string
	CacheAddr        string
	CacheFile        string
	Listeners        []Listener
	Ipv4Disable      bool
	Ipv6Disable      bool
	TcpDisable       bool
	RateLimit        int
	StaleAge         int
	NegativeTTL      int
	TTLMin           int
	TTLMax           int
	CacheMaxEntries  int
	UpstreamPoolSize int
	UpstreamPoolIdle int
	LogLevel         string
	LogMode          string
	LogDir           string
	LogRetention     int
	TimeZone         string
	CacheWarmup          bool
	MaxTCPConnsPerClient int
	MetricsEnable        bool
	MetricsPort          int
	ConfigPath       string
	Hooks            HookConfig
}

func Load() Config {
	loadDotEnv()

	cfgPath := "./northstar.yaml"
	if v, ok := os.LookupEnv("NORTHSTAR_CONFIG"); ok && v != "" {
		cfgPath = v
	}

	cfg := Config{
		ConfigPath:       cfgPath,
		Mode:             "prod",
		DNSPort:          53,
		UpstreamAddr:     "8.8.8.8:53",
		CacheAddr:        "",
		CacheFile:        "",
		Ipv4Disable:      false,
		Ipv6Disable:      false,
		TcpDisable:       false,
		RateLimit:        0,
		StaleAge:         60,
		NegativeTTL:      0,
		TTLMin:           0,
		TTLMax:           0,
		CacheMaxEntries:  0,
		UpstreamPoolSize: 10,
		UpstreamPoolIdle: 30,
		LogLevel:         "",
		LogMode:          "",
		LogDir:           ".",
		LogRetention:     7,
		TimeZone:         "",
		CacheWarmup:          false,
		MaxTCPConnsPerClient: 0,
		MetricsEnable:        false,
		MetricsPort:          9153,
		Hooks: HookConfig{
			RateLimiting: RateLimitHookConfig{
				Enabled:  false,
				Priority: 100,
				Rate:     0,
				Action:   "servfail",
			},
		},
	}

	if fc, err := loadFile(cfgPath); err == nil {
		applyFileConfig(&cfg, fc)
	}

	applyEnvOverrides(&cfg)

	if cfg.Ipv4Disable && cfg.Ipv6Disable {
		panic("No IP addresses provided. Please set either NORTHSTAR_DNS_IPV4_DISABLE or NORTHSTAR_DNS_IPV6_DISABLE to false")
	}

	cfg.Listeners = buildListeners(cfg.DNSPort, cfg.Ipv4Disable, cfg.Ipv6Disable)

	return cfg
}

func Reload() (Config, error) {
	loadDotEnv()

	cfgPath := "./northstar.yaml"
	if v, ok := os.LookupEnv("NORTHSTAR_CONFIG"); ok && v != "" {
		cfgPath = v
	}

	cfg := Config{
		ConfigPath:       cfgPath,
		Mode:             "prod",
		DNSPort:          53,
		UpstreamAddr:     "8.8.8.8:53",
		CacheAddr:        "",
		CacheFile:        "",
		Ipv4Disable:      false,
		Ipv6Disable:      false,
		TcpDisable:       false,
		RateLimit:        0,
		StaleAge:         60,
		NegativeTTL:      0,
		TTLMin:           0,
		TTLMax:           0,
		CacheMaxEntries:  0,
		UpstreamPoolSize: 10,
		UpstreamPoolIdle: 30,
		LogLevel:         "",
		LogMode:          "",
		LogDir:           ".",
		LogRetention:     7,
		TimeZone:         "",
		CacheWarmup:          false,
		MaxTCPConnsPerClient: 0,
		MetricsEnable:        false,
		MetricsPort:          9153,
		Hooks: HookConfig{
			RateLimiting: RateLimitHookConfig{
				Enabled:  false,
				Priority: 100,
				Rate:     0,
				Action:   "servfail",
			},
		},
	}

	if fc, err := loadFile(cfgPath); err == nil {
		applyFileConfig(&cfg, fc)
	}

	applyEnvOverrides(&cfg)

	if cfg.Ipv4Disable && cfg.Ipv6Disable {
		return cfg, fmt.Errorf("both IPv4 and IPv6 are disabled")
	}

	cfg.Listeners = buildListeners(cfg.DNSPort, cfg.Ipv4Disable, cfg.Ipv6Disable)

	return cfg, nil
}

func loadDotEnv() {
	if envMap, err := godotenv.Read(); err == nil {
		for k, v := range envMap {
			if os.Getenv(k) == "" {
				if err := os.Setenv(k, v); err != nil {
					panic(fmt.Sprintf("invalid env var %s: %v", k, err))
				}
			}
		}
	}
}

func applyEnvOverrides(cfg *Config) {
	if v, ok := os.LookupEnv("NORTHSTAR_MODE"); ok {
		cfg.Mode = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_PORT"); ok {
		cfg.DNSPort = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_UPSTREAM"); ok {
		cfg.UpstreamAddr = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_CACHE_ADDR"); ok {
		cfg.CacheAddr = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_CACHE_FILE"); ok {
		cfg.CacheFile = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_IPV4_DISABLE"); ok {
		cfg.Ipv4Disable = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_IPV6_DISABLE"); ok {
		cfg.Ipv6Disable = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TCP_DISABLE"); ok {
		cfg.TcpDisable = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_RATE_LIMIT"); ok {
		cfg.RateLimit = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_STALE_AGE"); ok {
		cfg.StaleAge = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_NEGATIVE_TTL"); ok {
		cfg.NegativeTTL = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_CACHE_MAX_ENTRIES"); ok {
		cfg.CacheMaxEntries = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_TTL_MIN"); ok {
		cfg.TTLMin = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_TTL_MAX"); ok {
		cfg.TTLMax = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_UPSTREAM_POOL_SIZE"); ok {
		cfg.UpstreamPoolSize = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_UPSTREAM_POOL_IDLE"); ok {
		cfg.UpstreamPoolIdle = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_LOG_LEVEL"); ok {
		cfg.LogLevel = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_LOG_MODE"); ok {
		cfg.LogMode = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_LOG_DIR"); ok {
		cfg.LogDir = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_LOG_RETENTION"); ok {
		cfg.LogRetention = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TZ"); ok {
		cfg.TimeZone = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_CACHE_WARMUP"); ok {
		cfg.CacheWarmup = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_MAX_TCP_CONNS_PER_CLIENT"); ok {
		cfg.MaxTCPConnsPerClient = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_METRICS_ENABLE"); ok {
		cfg.MetricsEnable = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_METRICS_PORT"); ok {
		cfg.MetricsPort = atoiOrZero(v)
	}
	// ConfigPath override (not from file, directly via env)
	if v, ok := os.LookupEnv("NORTHSTAR_CONFIG"); ok {
		cfg.ConfigPath = v
	}
}

func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func isTrue(s string) bool {
	return strings.EqualFold(s, "true")
}

func buildListeners(port int, disableIPv4, disableIPv6 bool) []Listener {
	if !disableIPv4 && !disableIPv6 {
		return []Listener{{IP: "::", Port: port}}
	}
	var listeners []Listener
	if !disableIPv4 {
		listeners = append(listeners, Listener{IP: "0.0.0.0", Port: port})
	}
	if !disableIPv6 {
		listeners = append(listeners, Listener{IP: "::", Port: port})
	}
	return listeners
}
