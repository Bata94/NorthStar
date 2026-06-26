package cache

import (
	"context"
	"math"
	"sync"
	"time"
)

type TokenBucket interface {
	TryConsume(ctx context.Context, clientIP string) (bool, error)
	Close() error
}

type memoryBucket struct {
	mu         sync.Mutex
	tokens     float64
	lastRefill time.Time
	lastAccess time.Time
}

type MemoryTokenBucket struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*memoryBucket
	closeCh chan struct{}
	closed  bool
}

func NewMemoryTokenBucket(rate, burst int) *MemoryTokenBucket {
	mtb := &MemoryTokenBucket{
		rate:    float64(rate),
		burst:   float64(burst),
		buckets: make(map[string]*memoryBucket),
		closeCh: make(chan struct{}),
	}
	if mtb.burst < 1 {
		mtb.burst = mtb.rate
	}
	go mtb.sweeper()
	return mtb
}

func (mtb *MemoryTokenBucket) TryConsume(_ context.Context, clientIP string) (bool, error) {
	mtb.mu.Lock()
	b, ok := mtb.buckets[clientIP]
	if !ok {
		b = &memoryBucket{
			tokens:     mtb.burst,
			lastRefill: time.Now(),
		}
		mtb.buckets[clientIP] = b
	}
	mtb.mu.Unlock()

	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens = math.Min(mtb.burst, b.tokens+elapsed*mtb.rate)
	b.lastRefill = now
	b.lastAccess = now

	if b.tokens >= 1 {
		b.tokens--
		return true, nil
	}
	return false, nil
}

func (mtb *MemoryTokenBucket) sweeper() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			mtb.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for ip, b := range mtb.buckets {
				b.mu.Lock()
				if b.lastAccess.Before(cutoff) {
					delete(mtb.buckets, ip)
				}
				b.mu.Unlock()
			}
			mtb.mu.Unlock()
		case <-mtb.closeCh:
			return
		}
	}
}

func (mtb *MemoryTokenBucket) Close() error {
	mtb.mu.Lock()
	defer mtb.mu.Unlock()
	if !mtb.closed {
		close(mtb.closeCh)
		mtb.closed = true
	}
	return nil
}

var _ TokenBucket = (*MemoryTokenBucket)(nil)
