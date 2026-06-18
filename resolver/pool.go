// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package resolver

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

type idleConn struct {
	conn     net.Conn
	returned time.Time
}

type Pool struct {
	mu       sync.Mutex
	idle     []idleConn
	upstream string
	network  string
	maxIdle  int
	idleTO   time.Duration
	closed   bool
	stopCh   chan struct{}
}

func NewPool(upstream, network string, maxIdle int, idleTO time.Duration) *Pool {
	p := &Pool{
		upstream: upstream,
		network:  network,
		maxIdle:  maxIdle,
		idleTO:   idleTO,
		stopCh:   make(chan struct{}),
	}
	if maxIdle > 0 && idleTO > 0 {
		go p.sweeper()
	}
	return p
}

func (p *Pool) Acquire(ctx context.Context) (net.Conn, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	if len(p.idle) > 0 {
		ic := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		p.mu.Unlock()
		return ic.conn, nil
	}
	p.mu.Unlock()

	var d net.Dialer
	return d.DialContext(ctx, p.network, p.upstream)
}

func (p *Pool) Release(conn net.Conn, err error) {
	if err != nil {
		if err := conn.Close(); err != nil {
			slog.Error("Error closing upstream conn", "error", err)
		}
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed || len(p.idle) >= p.maxIdle {
		if err := conn.Close(); err != nil {
			slog.Error("Error closing upstream conn", "error", err)
		}
		return
	}
	p.idle = append(p.idle, idleConn{conn: conn, returned: time.Now()})
}

func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	close(p.stopCh)
	for _, ic := range idle {
		if err := ic.conn.Close(); err != nil {
			slog.Error("Error closing upstream conn", "error", err)
		}
	}
}

func (p *Pool) sweeper() {
	tick := p.idleTO / 2
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.mu.Lock()
			now := time.Now()
			keep := p.idle[:0]
			for _, ic := range p.idle {
				if now.Sub(ic.returned) > p.idleTO {
					if err := ic.conn.Close(); err != nil {
						slog.Error("Error closing idle upstream conn", "error", err)
					}
				} else {
					keep = append(keep, ic)
				}
			}
			p.idle = keep
			p.mu.Unlock()
		}
	}
}
