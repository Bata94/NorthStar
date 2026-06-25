// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package pool

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func startTestUpstream(t *testing.T, network string) (net.Addr, func()) {
	t.Helper()
	var l net.Listener
	var err error

	switch network {
	case "tcp":
		l, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				conn, aErr := l.Accept()
				if aErr != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	default:
		addr, aErr := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		if aErr != nil {
			t.Fatal(aErr)
		}
		conn, aErr := net.ListenUDP("udp", addr)
		if aErr != nil {
			t.Fatal(aErr)
		}
		go func() {
			buf := make([]byte, 1500)
			for {
				_, rAddr, rErr := conn.ReadFromUDP(buf)
				if rErr != nil {
					return
				}
				_, _ = conn.WriteToUDP(nil, rAddr)
			}
		}()
		return conn.LocalAddr(), func() { _ = conn.Close() }
	}

	return l.Addr(), func() { _ = l.Close() }
}

func TestPoolAcquireRelease(t *testing.T) {
	addr, cleanup := startTestUpstream(t, "tcp")
	defer cleanup()

	p := New(addr.String(), "tcp", 5, time.Minute)
	defer p.Close()

	ctx := context.Background()
	conn, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}

	p.Release(conn, nil)

	p.mu.Lock()
	idleCount := len(p.idle)
	p.mu.Unlock()

	if idleCount != 1 {
		t.Errorf("expected 1 idle conn, got %d", idleCount)
	}
}

func TestPoolReusesIdleConn(t *testing.T) {
	addr, cleanup := startTestUpstream(t, "tcp")
	defer cleanup()

	p := New(addr.String(), "tcp", 5, time.Minute)
	defer p.Close()

	ctx := context.Background()
	conn1, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.Release(conn1, nil)

	conn2, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if conn2 != conn1 {
		t.Error("expected same conn (idle reuse)")
	}
	p.Release(conn2, nil)
}

func TestPoolOverflowCloses(t *testing.T) {
	addr, cleanup := startTestUpstream(t, "tcp")
	defer cleanup()

	p := New(addr.String(), "tcp", 1, time.Minute)
	defer p.Close()

	ctx := context.Background()
	conn1, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn2, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}

	p.Release(conn1, nil)
	p.Release(conn2, nil)

	p.mu.Lock()
	idleCount := len(p.idle)
	p.mu.Unlock()

	if idleCount != 1 {
		t.Errorf("expected 1 idle conn (overflow closed), got %d", idleCount)
	}
}

func TestPoolErrorReleaseCloses(t *testing.T) {
	addr, cleanup := startTestUpstream(t, "tcp")
	defer cleanup()

	p := New(addr.String(), "tcp", 5, time.Minute)
	defer p.Close()

	ctx := context.Background()
	conn, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}

	p.Release(conn, net.ErrClosed)

	p.mu.Lock()
	idleCount := len(p.idle)
	p.mu.Unlock()

	if idleCount != 0 {
		t.Errorf("expected 0 idle conn (error release closes), got %d", idleCount)
	}
}

func TestPoolClosedReturnsErrClosed(t *testing.T) {
	addr, cleanup := startTestUpstream(t, "tcp")
	defer cleanup()

	p := New(addr.String(), "tcp", 5, time.Minute)
	p.Close()

	_, err := p.Acquire(context.Background())
	if err != net.ErrClosed {
		t.Errorf("expected net.ErrClosed, got %v", err)
	}
}

func TestPoolCloseClosesIdle(t *testing.T) {
	addr, cleanup := startTestUpstream(t, "tcp")
	defer cleanup()

	p := New(addr.String(), "tcp", 5, time.Minute)

	ctx := context.Background()
	conn, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.Release(conn, nil)

	p.Close()

	p.mu.Lock()
	idleCount := len(p.idle)
	p.mu.Unlock()

	if idleCount != 0 {
		t.Errorf("expected 0 idle after close, got %d", idleCount)
	}
}

func TestPoolSweeperEvictsStale(t *testing.T) {
	addr, cleanup := startTestUpstream(t, "tcp")
	defer cleanup()

	p := New(addr.String(), "tcp", 5, 50*time.Millisecond)
	defer p.Close()

	ctx := context.Background()
	conn, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.Release(conn, nil)

	time.Sleep(200 * time.Millisecond)

	p.mu.Lock()
	idleCount := len(p.idle)
	p.mu.Unlock()

	if idleCount != 0 {
		t.Errorf("expected sweeper to evict stale conn, got %d idle", idleCount)
	}
}

func TestPoolConcurrent(t *testing.T) {
	addr, cleanup := startTestUpstream(t, "tcp")
	defer cleanup()

	p := New(addr.String(), "tcp", 10, time.Minute)
	defer p.Close()

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := p.Acquire(ctx)
			if err != nil {
				return
			}
			time.Sleep(time.Millisecond)
			p.Release(conn, nil)
		}()
	}
	wg.Wait()
}

func TestPoolNoSweeperWhenDisabled(t *testing.T) {
	addr, cleanup := startTestUpstream(t, "tcp")
	defer cleanup()

	p := New(addr.String(), "tcp", 0, 0)
	defer p.Close()

	if p.stopCh == nil {
		t.Error("stopCh should exist even without sweeper")
	}
}
