// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package config

import (
	"sync/atomic"
)

type RuntimeConfig struct {
	RateLimit   atomic.Int64
	StaleAge    atomic.Int64
	NegativeTTL atomic.Int64
	TTLMin      atomic.Int64
	TTLMax      atomic.Int64
	LogLevel  atomic.Value
	LogMode   atomic.Value
}

func NewRuntimeConfig(cfg *Config) *RuntimeConfig {
	rc := &RuntimeConfig{}
	rc.ApplyConfig(cfg)
	return rc
}

func (rc *RuntimeConfig) ApplyConfig(cfg *Config) {
	rc.RateLimit.Store(int64(cfg.RateLimit))
	rc.StaleAge.Store(int64(cfg.StaleAge))
	rc.NegativeTTL.Store(int64(cfg.NegativeTTL))
	rc.TTLMin.Store(int64(cfg.TTLMin))
	rc.TTLMax.Store(int64(cfg.TTLMax))
	rc.LogLevel.Store(cfg.LogLevel)
	rc.LogMode.Store(cfg.LogMode)
}
