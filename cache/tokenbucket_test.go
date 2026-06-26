package cache

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryTokenBucketConsume(t *testing.T) {
	tb := NewMemoryTokenBucket(10, 10)
	defer func() { _ = tb.Close() }()

	ctx := context.Background()

	for i := 0; i < 10; i++ {
		ok, err := tb.TryConsume(ctx, "10.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatalf("call %d: expected allowed, got denied", i)
		}
	}

	ok, err := tb.TryConsume(ctx, "10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected denied after burst exhausted")
	}
}

func TestMemoryTokenBucketRefill(t *testing.T) {
	tb := NewMemoryTokenBucket(100, 10)
	defer func() { _ = tb.Close() }()

	ctx := context.Background()

	for i := 0; i < 10; i++ {
		_, _ = tb.TryConsume(ctx, "10.0.0.1")
	}

	tb.mu.Lock()
	b := tb.buckets["10.0.0.1"]
	tb.mu.Unlock()

	b.mu.Lock()
	b.lastRefill = b.lastRefill.Add(-time.Second)
	b.mu.Unlock()

	for i := 0; i < 10; i++ {
		ok, err := tb.TryConsume(ctx, "10.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatalf("call %d: expected allowed after refill, got denied", i)
		}
	}
}

func TestMemoryTokenBucketIsolation(t *testing.T) {
	tb := NewMemoryTokenBucket(5, 5)
	defer func() { _ = tb.Close() }()

	ctx := context.Background()

	for i := 0; i < 5; i++ {
		ok, err := tb.TryConsume(ctx, "10.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatalf("client1 call %d: expected allowed", i)
		}
	}

	ok, err := tb.TryConsume(ctx, "10.0.0.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("client2 should have full burst independently")
	}
}

func TestMemoryTokenBucketCloseIdempotent(t *testing.T) {
	tb := NewMemoryTokenBucket(10, 10)
	if err := tb.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := tb.Close(); err != nil {
		t.Fatalf("second close should be idempotent: %v", err)
	}
}

func TestMemoryTokenBucketConcurrent(t *testing.T) {
	tb := NewMemoryTokenBucket(0, 1000)
	defer func() { _ = tb.Close() }()

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_, _ = tb.TryConsume(ctx, "10.0.0.1")
			}
		}()
	}
	wg.Wait()

	ok, err := tb.TryConsume(ctx, "10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected denied after concurrent burst exhaustion")
	}
}

func TestTokenBucketInterface(t *testing.T) {
	tb := NewMemoryTokenBucket(10, 10)
	defer func() { _ = tb.Close() }()

	var iface TokenBucket = tb
	ctx := context.Background()
	ok, err := iface.TryConsume(ctx, "10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected first call to succeed")
	}
}
