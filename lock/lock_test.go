package lock

import (
	"context"
	"testing"
	"time"
)

func TestInProcessMutex_TryLock(t *testing.T) {
	m := NewInProcessMutex()
	ctx := context.Background()

	locked, err := m.TryLock(ctx)
	if err != nil {
		t.Fatalf("first TryLock: %v", err)
	}
	if !locked {
		t.Fatal("expected to acquire lock")
	}

	locked, err = m.TryLock(ctx)
	if err != nil {
		t.Fatalf("second TryLock: %v", err)
	}
	if locked {
		t.Fatal("expected lock to be held")
	}
}

func TestInProcessMutex_Unlock(t *testing.T) {
	m := NewInProcessMutex()
	ctx := context.Background()

	_, _ = m.TryLock(ctx)
	if err := m.Unlock(ctx); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	locked, err := m.TryLock(ctx)
	if err != nil {
		t.Fatalf("TryLock after Unlock: %v", err)
	}
	if !locked {
		t.Fatal("expected to acquire lock after Unlock")
	}
}

func TestInProcessMutex_DoubleUnlock(t *testing.T) {
	m := NewInProcessMutex()
	ctx := context.Background()

	_, _ = m.TryLock(ctx)
	_ = m.Unlock(ctx)
	if err := m.Unlock(ctx); err != nil {
		t.Fatalf("double Unlock should not error: %v", err)
	}

	locked, _ := m.TryLock(ctx)
	if !locked {
		t.Fatal("expected to acquire lock after double Unlock")
	}
}

func TestInProcessMutex_Refresh(t *testing.T) {
	m := NewInProcessMutex()
	if err := m.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
}

func TestInProcessMutex_Concurrent(t *testing.T) {
	m := NewInProcessMutex()
	ctx := context.Background()

	_, _ = m.TryLock(ctx)

	done := make(chan struct{})
	go func() {
		defer close(done)
		locked, _ := m.TryLock(ctx)
		if locked {
			t.Error("second goroutine should not acquire held lock")
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TryLock on held lock should not block")
	}

	_ = m.Unlock(ctx)

	locked, _ := m.TryLock(ctx)
	if !locked {
		t.Fatal("expected to acquire lock after Unlock")
	}
	_ = m.Unlock(ctx)
}

func TestInProcessMutex_BlockedAfterLock(t *testing.T) {
	m := NewInProcessMutex()
	ctx := context.Background()

	_, _ = m.TryLock(ctx)

	done := make(chan struct{})
	go func() {
		_ = m.Unlock(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Unlock should not block")
	}

	locked, _ := m.TryLock(ctx)
	if !locked {
		t.Fatal("expected to acquire lock after concurrent Unlock")
	}
	_ = m.Unlock(ctx)
}
