// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package resolver

import (
	"time"

	"github.com/bata94/northstar/pool"
)

type Pool = pool.Pool

func NewPool(upstream, network string, maxIdle int, idleTO time.Duration) *Pool {
	return pool.New(upstream, network, maxIdle, idleTO)
}
