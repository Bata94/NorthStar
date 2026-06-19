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

type Config struct {
	Mode             string
	DNSPort          int
	UpstreamAddr     string
	CacheAddr        string
	Listeners        []Listener
	Ipv4Disable      bool
	Ipv6Disable      bool
	TcpDisable       bool
	RateLimit        int
	StaleAge         int
	UpstreamPoolSize int
	UpstreamPoolIdle int
	LogLevel         string
	LogMode          string
	LogDir           string
	LogRetention     int
	TimeZone         string
	MetricsEnable    bool
	MetricsPort      int
}

func Load() Config {
	if envMap, err := godotenv.Read(); err == nil {
		for k, v := range envMap {
			if os.Getenv(k) == "" {
				if err := os.Setenv(k, v); err != nil {
					panic(fmt.Sprintf("invalid env var %s: %v", k, err))
				}
			}
		}
	}

	cfg := Config{
		Mode:         getEnv("NORTHSTAR_MODE", "prod"),
		DNSPort:      getEnvInt("NORTHSTAR_DNS_PORT", 53),
		UpstreamAddr: getEnv("NORTHSTAR_UPSTREAM", "8.8.8.8:53"),
		CacheAddr:    getEnv("NORTHSTAR_CACHE_ADDR", ""),
		LogLevel:     getEnv("NORTHSTAR_LOG_LEVEL", ""),
		LogMode:      getEnv("NORTHSTAR_LOG_MODE", ""),
		LogDir:       getEnv("NORTHSTAR_LOG_DIR", "."),
		LogRetention: getEnvInt("NORTHSTAR_LOG_RETENTION", 7),
		TimeZone:     getEnv("NORTHSTAR_TZ", ""),
	}

	cfg.Ipv4Disable = getEnvBool("NORTHSTAR_DNS_IPV4_DISABLE")
	cfg.Ipv6Disable = getEnvBool("NORTHSTAR_DNS_IPV6_DISABLE")

	if cfg.Ipv4Disable && cfg.Ipv6Disable {
		panic("No IP addresses provided. Please set either NORTHSTAR_DNS_IPV4_DISABLE or NORTHSTAR_DNS_IPV6_DISABLE to false")
	}

	cfg.TcpDisable = getEnvBool("NORTHSTAR_TCP_DISABLE")

	cfg.RateLimit = getEnvInt("NORTHSTAR_DNS_RATE_LIMIT", 0)
	cfg.StaleAge = getEnvInt("NORTHSTAR_DNS_STALE_AGE", 60)
	cfg.UpstreamPoolSize = getEnvInt("NORTHSTAR_UPSTREAM_POOL_SIZE", 10)
	cfg.UpstreamPoolIdle = getEnvInt("NORTHSTAR_UPSTREAM_POOL_IDLE", 30)

	cfg.MetricsEnable = getEnvBool("NORTHSTAR_METRICS_ENABLE")
	cfg.MetricsPort = getEnvInt("NORTHSTAR_METRICS_PORT", 9153)

	cfg.Listeners = buildListeners(cfg.DNSPort, cfg.Ipv4Disable, cfg.Ipv6Disable)

	return cfg
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getEnvBool(key string) bool {
	return strings.EqualFold(getEnv(key, ""), "true")
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
