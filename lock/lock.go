package lock

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"
)

type Mutex struct {
	client  valkey.Client
	key     string
	ownerID string
	ttl     time.Duration
}

func NewMutex(client valkey.Client, key string, ttl time.Duration) *Mutex {
	b := make([]byte, 8)
	rand.Read(b)
	return &Mutex{
		client:  client,
		key:     key,
		ownerID: fmt.Sprintf("%x", b),
		ttl:     ttl,
	}
}

func (m *Mutex) TryLock(ctx context.Context) (bool, error) {
	err := m.client.Do(ctx, m.client.B().Set().Key(m.key).Value(m.ownerID).Nx().Ex(m.ttl).Build()).Error()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (m *Mutex) Unlock(ctx context.Context) error {
	script := valkey.NewLuaScript(`
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("DEL", KEYS[1])
		end
		return 0
	`)
	return script.Exec(ctx, m.client, []string{m.key}, []string{m.ownerID}).Error()
}

func (m *Mutex) Refresh(ctx context.Context) error {
	script := valkey.NewLuaScript(`
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("EXPIRE", KEYS[1], ARGV[2])
		end
		return 0
	`)
	return script.Exec(ctx, m.client, []string{m.key}, []string{m.ownerID, fmt.Sprintf("%d", int64(m.ttl.Seconds()))}).Error()
}

type InProcessMutex struct {
	mu     sync.Mutex
	locked bool
}

func NewInProcessMutex() *InProcessMutex {
	return &InProcessMutex{}
}

func (m *InProcessMutex) TryLock(_ context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return false, nil
	}
	m.locked = true
	return true, nil
}

func (m *InProcessMutex) Unlock(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.locked = false
	return nil
}

func (m *InProcessMutex) Refresh(_ context.Context) error {
	return nil
}
