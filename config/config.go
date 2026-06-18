package config

import (
	"fmt"
	"os"
	"strconv"

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
	}

	if getEnv("NORTHSTAR_DNS_IPV4_DISABLE", "") == "true" {
		cfg.Ipv4Disable = true
	}
	if getEnv("NORTHSTAR_DNS_IPV6_DISABLE", "") == "true" {
		cfg.Ipv6Disable = true
	}

	if cfg.Ipv4Disable && cfg.Ipv6Disable {
		panic("No IP addresses provided. Please set either NORTHSTAR_DNS_IPV4_DISABLE or NORTHSTAR_DNS_IPV6_DISABLE to false")
	}

	if getEnv("NORTHSTAR_TCP_DISABLE", "") == "true" {
		cfg.TcpDisable = true
	}

	cfg.RateLimit = getEnvInt("NORTHSTAR_DNS_RATE_LIMIT", 0)
	cfg.StaleAge = getEnvInt("NORTHSTAR_DNS_STALE_AGE", 60)
	cfg.UpstreamPoolSize = getEnvInt("NORTHSTAR_UPSTREAM_POOL_SIZE", 10)
	cfg.UpstreamPoolIdle = getEnvInt("NORTHSTAR_UPSTREAM_POOL_IDLE", 30)

	if getEnv("NORTHSTAR_METRICS_ENABLE", "") == "true" {
		cfg.MetricsEnable = true
	}
	cfg.MetricsPort = getEnvInt("NORTHSTAR_METRICS_PORT", 9153)

	if !cfg.Ipv4Disable && !cfg.Ipv6Disable {
		cfg.Listeners = append(cfg.Listeners, Listener{IP: "::", Port: cfg.DNSPort})
	} else {
		if !cfg.Ipv4Disable {
			cfg.Listeners = append(cfg.Listeners, Listener{IP: "0.0.0.0", Port: cfg.DNSPort})
		}
		if !cfg.Ipv6Disable {
			cfg.Listeners = append(cfg.Listeners, Listener{IP: "::", Port: cfg.DNSPort})
		}
	}

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
