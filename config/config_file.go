// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package config

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

type FileHookConfig struct {
	RateLimiting FileRateLimitHookConfig `yaml:"rate_limiting"`
}

type FileRateLimitHookConfig struct {
	Enabled  *bool   `yaml:"enabled"`
	Priority *int    `yaml:"priority"`
	Rate     *int    `yaml:"rate"`
	Action   *string `yaml:"action"`
}

type FileConfig struct {
	Mode             *string                `yaml:"mode"`
	DNSPort          *int            `yaml:"dns_port"`
	UpstreamAddr     *string         `yaml:"upstream"`
	CacheAddr        *string         `yaml:"cache_addr"`
	CacheFile        *string         `yaml:"cache_file"`
	Ipv4Disable      *bool           `yaml:"ipv4_disable"`
	Ipv6Disable      *bool           `yaml:"ipv6_disable"`
	TcpDisable       *bool           `yaml:"tcp_disable"`
	RateLimit        *int            `yaml:"rate_limit"`
	StaleAge         *int            `yaml:"stale_age"`
	NegativeTTL      *int            `yaml:"negative_ttl"`
	CacheWarmup      *bool           `yaml:"cache_warmup"`
	CacheMaxEntries  *int            `yaml:"cache_max_entries"`
	TTLMin           *int            `yaml:"ttl_min"`
	TTLMax           *int            `yaml:"ttl_max"`
	UpstreamPoolSize *int            `yaml:"upstream_pool_size"`
	UpstreamPoolIdle *int            `yaml:"upstream_pool_idle"`
	LogLevel         *string         `yaml:"log_level"`
	LogMode          *string         `yaml:"log_mode"`
	LogDir           *string         `yaml:"log_dir"`
	LogRetention     *int            `yaml:"log_retention"`
	TimeZone             *string         `yaml:"timezone"`
	MaxTCPConnsPerClient *int            `yaml:"max_tcp_conns_per_client"`
	MetricsEnable        *bool           `yaml:"metrics_enable"`
	MetricsPort      *int            `yaml:"metrics_port"`
	Hooks            *FileHookConfig `yaml:"hooks"`
}

func loadFile(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fc FileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &fc, nil
}

func applyFileConfig(cfg *Config, fc *FileConfig) {
	if fc.Mode != nil {
		cfg.Mode = *fc.Mode
	}
	if fc.DNSPort != nil {
		cfg.DNSPort = *fc.DNSPort
	}
	if fc.UpstreamAddr != nil {
		cfg.UpstreamAddr = *fc.UpstreamAddr
	}
	if fc.CacheAddr != nil {
		cfg.CacheAddr = *fc.CacheAddr
	}
	if fc.CacheFile != nil {
		cfg.CacheFile = *fc.CacheFile
	}
	if fc.Ipv4Disable != nil {
		cfg.Ipv4Disable = *fc.Ipv4Disable
	}
	if fc.Ipv6Disable != nil {
		cfg.Ipv6Disable = *fc.Ipv6Disable
	}
	if fc.TcpDisable != nil {
		cfg.TcpDisable = *fc.TcpDisable
	}
	if fc.RateLimit != nil {
		cfg.RateLimit = *fc.RateLimit
	}
	if fc.StaleAge != nil {
		cfg.StaleAge = *fc.StaleAge
	}
	if fc.NegativeTTL != nil {
		cfg.NegativeTTL = *fc.NegativeTTL
	}
	if fc.CacheWarmup != nil {
		cfg.CacheWarmup = *fc.CacheWarmup
	}
	if fc.CacheMaxEntries != nil {
		cfg.CacheMaxEntries = *fc.CacheMaxEntries
	}
	if fc.TTLMin != nil {
		cfg.TTLMin = *fc.TTLMin
	}
	if fc.TTLMax != nil {
		cfg.TTLMax = *fc.TTLMax
	}
	if fc.UpstreamPoolSize != nil {
		cfg.UpstreamPoolSize = *fc.UpstreamPoolSize
	}
	if fc.UpstreamPoolIdle != nil {
		cfg.UpstreamPoolIdle = *fc.UpstreamPoolIdle
	}
	if fc.LogLevel != nil {
		cfg.LogLevel = *fc.LogLevel
	}
	if fc.LogMode != nil {
		cfg.LogMode = *fc.LogMode
	}
	if fc.LogDir != nil {
		cfg.LogDir = *fc.LogDir
	}
	if fc.LogRetention != nil {
		cfg.LogRetention = *fc.LogRetention
	}
	if fc.TimeZone != nil {
		cfg.TimeZone = *fc.TimeZone
	}
	if fc.MaxTCPConnsPerClient != nil {
		cfg.MaxTCPConnsPerClient = *fc.MaxTCPConnsPerClient
	}
	if fc.MetricsEnable != nil {
		cfg.MetricsEnable = *fc.MetricsEnable
	}
	if fc.MetricsPort != nil {
		cfg.MetricsPort = *fc.MetricsPort
	}
	if fc.Hooks != nil {
		if fc.Hooks.RateLimiting.Enabled != nil {
			cfg.Hooks.RateLimiting.Enabled = *fc.Hooks.RateLimiting.Enabled
		}
		if fc.Hooks.RateLimiting.Priority != nil {
			cfg.Hooks.RateLimiting.Priority = *fc.Hooks.RateLimiting.Priority
		}
		if fc.Hooks.RateLimiting.Rate != nil {
			cfg.Hooks.RateLimiting.Rate = *fc.Hooks.RateLimiting.Rate
		}
		if fc.Hooks.RateLimiting.Action != nil {
			cfg.Hooks.RateLimiting.Action = *fc.Hooks.RateLimiting.Action
		}
	}
}

func configToFile(cfg *Config) *FileConfig {
	mode := cfg.Mode
	dnsPort := cfg.DNSPort
	upstream := cfg.UpstreamAddr
	cacheAddr := cfg.CacheAddr
	cacheFile := cfg.CacheFile
	ipv4Disable := cfg.Ipv4Disable
	ipv6Disable := cfg.Ipv6Disable
	tcpDisable := cfg.TcpDisable
	rateLimit := cfg.RateLimit
	staleAge := cfg.StaleAge
	negativeTTL := cfg.NegativeTTL
	cacheWarmup := cfg.CacheWarmup
	cacheMaxEntries := cfg.CacheMaxEntries
	ttlMin := cfg.TTLMin
	ttlMax := cfg.TTLMax
	upstreamPoolSize := cfg.UpstreamPoolSize
	upstreamPoolIdle := cfg.UpstreamPoolIdle
	logLevel := cfg.LogLevel
	logMode := cfg.LogMode
	logDir := cfg.LogDir
	logRetention := cfg.LogRetention
	timeZone := cfg.TimeZone
	maxTCPConnsPerClient := cfg.MaxTCPConnsPerClient
	metricsEnable := cfg.MetricsEnable
	metricsPort := cfg.MetricsPort
	hookEnabled := cfg.Hooks.RateLimiting.Enabled
	hookPriority := cfg.Hooks.RateLimiting.Priority
	hookRate := cfg.Hooks.RateLimiting.Rate
	hookAction := cfg.Hooks.RateLimiting.Action

	return &FileConfig{
		Mode:             &mode,
		DNSPort:          &dnsPort,
		UpstreamAddr:     &upstream,
		CacheAddr:        &cacheAddr,
		CacheFile:        &cacheFile,
		Ipv4Disable:      &ipv4Disable,
		Ipv6Disable:      &ipv6Disable,
		TcpDisable:       &tcpDisable,
		RateLimit:        &rateLimit,
		StaleAge:         &staleAge,
		NegativeTTL:      &negativeTTL,
		CacheWarmup:      &cacheWarmup,
		CacheMaxEntries:  &cacheMaxEntries,
		TTLMin:           &ttlMin,
		TTLMax:           &ttlMax,
		UpstreamPoolSize: &upstreamPoolSize,
		UpstreamPoolIdle: &upstreamPoolIdle,
		LogLevel:         &logLevel,
		LogMode:          &logMode,
		LogDir:           &logDir,
		LogRetention:     &logRetention,
		TimeZone:             &timeZone,
		MaxTCPConnsPerClient: &maxTCPConnsPerClient,
		MetricsEnable:        &metricsEnable,
		MetricsPort:      &metricsPort,
		Hooks: &FileHookConfig{
			RateLimiting: FileRateLimitHookConfig{
				Enabled:  &hookEnabled,
				Priority: &hookPriority,
				Rate:     &hookRate,
				Action:   &hookAction,
			},
		},
	}
}

func writeFile(path string, fc *FileConfig) error {
	data, err := yaml.Marshal(fc)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	header := `# northstar configuration
#
# Environment variables override every value in this file.
# Hierarchy (highest to lowest):
#   1. NORTHSTAR_* environment variables
#   2. Values in this file
#   3. Built-in defaults
#
# To use this file: place it at ./northstar.yaml or set
# the NORTHSTAR_CONFIG env var to a custom path.
# If no config file exists, this file is auto-generated on startup.
# You only need to uncomment and change the values you want to override.

`
	return os.WriteFile(path, append([]byte(header), data...), 0644)
}

func WriteEffectiveConfig(path string, cfg *Config) error {
	return writeFile(path, configToFile(cfg))
}

func WriteDefaultConfig(path string) error {
	mode := "prod"
	dnsPort := 53
	upstream := "8.8.8.8:53"
	cacheAddr := ""
	cacheFile := ""
	ipv4Disable := false
	ipv6Disable := false
	tcpDisable := false
	rateLimit := 0
	staleAge := 60
	negativeTTL := 0
	cacheWarmup := false
	cacheMaxEntries := 0
	ttlMin := 0
	ttlMax := 0
	upstreamPoolSize := 10
	upstreamPoolIdle := 30
	logLevel := ""
	logMode := ""
	logDir := "."
	logRetention := 7
	timeZone := ""
	maxTCPConnsPerClient := 0
	metricsEnable := false
	metricsPort := 9153
	hookEnabled := false
	hookPriority := 100
	hookRate := 0
	hookAction := "servfail"

	fc := FileConfig{
		Mode:             &mode,
		DNSPort:          &dnsPort,
		UpstreamAddr:     &upstream,
		CacheAddr:        &cacheAddr,
		CacheFile:        &cacheFile,
		Ipv4Disable:      &ipv4Disable,
		Ipv6Disable:      &ipv6Disable,
		TcpDisable:       &tcpDisable,
		RateLimit:        &rateLimit,
		StaleAge:         &staleAge,
		NegativeTTL:      &negativeTTL,
		CacheWarmup:      &cacheWarmup,
		CacheMaxEntries:  &cacheMaxEntries,
		TTLMin:           &ttlMin,
		TTLMax:           &ttlMax,
		UpstreamPoolSize: &upstreamPoolSize,
		UpstreamPoolIdle: &upstreamPoolIdle,
		LogLevel:         &logLevel,
		LogMode:          &logMode,
		LogDir:           &logDir,
		LogRetention:     &logRetention,
		TimeZone:             &timeZone,
		MaxTCPConnsPerClient: &maxTCPConnsPerClient,
		MetricsEnable:        &metricsEnable,
		MetricsPort:      &metricsPort,
		Hooks: &FileHookConfig{
			RateLimiting: FileRateLimitHookConfig{
				Enabled:  &hookEnabled,
				Priority: &hookPriority,
				Rate:     &hookRate,
				Action:   &hookAction,
			},
		},
	}

	return writeFile(path, &fc)
}
