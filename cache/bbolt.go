package cache

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bata94/northstar/dns"
	"go.etcd.io/bbolt"
)

type Bbolt struct {
	db       *bbolt.DB
	staleAge time.Duration
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

func NewBbolt(path string, staleAge int) (*Bbolt, error) {
	db, err := bbolt.Open(path, 0644, &bbolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("bbolt open: %w", err)
	}

	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("entries"))
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("bbolt bucket: %w", err)
	}

	b := &Bbolt{
		db:       db,
		staleAge: time.Duration(staleAge) * time.Second,
		stopCh:   make(chan struct{}),
	}
	b.wg.Add(1)
	go b.evictLoop()
	return b, nil
}

func (b *Bbolt) evictLoop() {
	defer b.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.evictExpired()
		case <-b.stopCh:
			return
		}
	}
}

func (b *Bbolt) evictExpired() {
	now := time.Now()
	if err := b.db.Update(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket([]byte("entries"))
		if bkt == nil {
			return nil
		}
		c := bkt.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(v) < 9 {
				continue
			}
			if v[0] != valkeyValueVer && v[0] != valkeyValueVer2 {
				continue
			}
			nano := int64(binary.BigEndian.Uint64(v[1:9]))
			if now.After(time.Unix(0, nano)) {
				if err := bkt.Delete(k); err != nil {
					slog.Error("bbolt evict delete", "error", err)
				}
			}
		}
		return nil
	}); err != nil {
		slog.Error("bbolt evict", "error", err)
	}
}

func (b *Bbolt) Delete(_ context.Context, domain string, qtype uint16) error {
	b.delete(domain, qtype)
	return nil
}

func (b *Bbolt) DeleteDomain(_ context.Context, domain string) error {
	prefix := []byte(domain + ":")
	return b.db.Update(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket([]byte("entries"))
		if bkt == nil {
			return nil
		}
		c := bkt.Cursor()
		for k, _ := c.Seek(prefix); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == string(prefix); k, _ = c.Next() {
			if err := bkt.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

func (b *Bbolt) Len() int {
	count := 0
	_ = b.db.View(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket([]byte("entries"))
		if bkt == nil {
			return nil
		}
		stats := bkt.Stats()
		count = stats.KeyN
		return nil
	})
	return count
}

func (b *Bbolt) Evictions() int64 {
	return 0
}

func (b *Bbolt) Get(_ context.Context, domain string, qtype uint16) (*Entry, bool) {
	entry, ok := b.peek(domain, qtype)
	if !ok {
		return nil, false
	}
	if entry.Expired() {
		b.delete(domain, qtype)
		return nil, false
	}
	return entry, true
}

func (b *Bbolt) Peek(_ context.Context, domain string, qtype uint16) (*Entry, bool) {
	return b.peek(domain, qtype)
}

func (b *Bbolt) peek(domain string, qtype uint16) (*Entry, bool) {
	key := b.key(domain, qtype)
	var data []byte

	if err := b.db.View(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket([]byte("entries"))
		if bkt == nil {
			return nil
		}
		v := bkt.Get(key)
		if v != nil {
			data = make([]byte, len(v))
			copy(data, v)
		}
		return nil
	}); err != nil {
		slog.Error("bbolt peek", "error", err)
		return nil, false
	}

	if data == nil {
		return nil, false
	}

	return decodeEntry(domain, qtype, data)
}

func (b *Bbolt) Set(_ context.Context, entry *Entry) error {
	key := b.key(entry.Domain, entry.QType)
	flags := entry.Flags
	if flags == 0 {
		flags = entry.RCode
		if entry.AuthenticData {
			flags |= 0x0020
		}
	}
	msg := dns.Message{
		Header: dns.Header{
			Flags:   flags,
			ANCount: uint16(len(entry.Answers)),
			NSCount: uint16(len(entry.Authorities)),
			ARCount: uint16(len(entry.Additionals)),
		},
		Answers:     entry.Answers,
		Authorities: entry.Authorities,
		Additionals: entry.Additionals,
	}
	wireData := msg.Pack()

	remaining := time.Until(entry.ExpiresAt)
	ttl := remaining + b.staleAge
	if ttl <= 0 {
		return nil
	}

	buf := make([]byte, 1+8+8+8+len(wireData))
	buf[0] = valkeyValueVer2
	binary.BigEndian.PutUint64(buf[1:9], uint64(entry.ExpiresAt.UnixNano()))
	binary.BigEndian.PutUint64(buf[9:17], uint64(entry.HitCount.Load()))
	binary.BigEndian.PutUint64(buf[17:25], uint64(entry.LastHitAt().UnixNano()))
	copy(buf[25:], wireData)

	return b.db.Update(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket([]byte("entries"))
		if bkt == nil {
			return nil
		}
		return bkt.Put(key, buf)
	})
}

func (b *Bbolt) Warmup(ctx context.Context, dest Cache) error {
	return b.db.View(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket([]byte("entries"))
		if bkt == nil {
			return nil
		}
		c := bkt.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			domain, qtype := parseBboltKey(string(k))
			if domain == "" {
				continue
			}
			entry, ok := decodeEntry(domain, qtype, v)
			if !ok || entry.Expired() {
				continue
			}
			if err := dest.Set(ctx, entry); err != nil {
				slog.Error("Bbolt warmup set", "error", err)
			}
		}
		return nil
	})
}

func parseBboltKey(key string) (string, uint16) {
	idx := strings.LastIndex(key, ":")
	if idx < 0 {
		return "", 0
	}
	domain := key[:idx]
	qtypeStr := key[idx+1:]
	var qtype uint16
	_, _ = fmt.Sscanf(qtypeStr, "%d", &qtype)
	return domain, qtype
}

func (b *Bbolt) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	bucketName := []byte("counters")
	if err := b.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	}); err != nil {
		return 0, fmt.Errorf("bbolt counters bucket: %w", err)
	}

	var val int64
	if err := b.db.Update(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket(bucketName)
		if bkt == nil {
			return nil
		}
		data := bkt.Get([]byte(key))
		now := time.Now()
		if len(data) >= 12 {
			expAt := int64(binary.BigEndian.Uint64(data[0:8]))
			if now.Before(time.Unix(0, expAt)) {
				val = int64(binary.BigEndian.Uint64(data[8:16])) + 1
			} else {
				val = 1
			}
		} else {
			val = 1
		}
		expiresAt := now.Add(ttl)
		newData := make([]byte, 16)
		binary.BigEndian.PutUint64(newData[0:8], uint64(expiresAt.UnixNano()))
		binary.BigEndian.PutUint64(newData[8:16], uint64(val))
		return bkt.Put([]byte(key), newData)
	}); err != nil {
		return 0, err
	}
	return val, nil
}

func (b *Bbolt) Close() {
	close(b.stopCh)
	b.wg.Wait()
	_ = b.db.Close()
}

func (b *Bbolt) key(domain string, qtype uint16) []byte {
	return []byte(fmt.Sprintf("%s:%d", domain, qtype))
}

func (b *Bbolt) delete(domain string, qtype uint16) {
	key := b.key(domain, qtype)
	_ = b.db.Update(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket([]byte("entries"))
		if bkt == nil {
			return nil
		}
		return bkt.Delete(key)
	})
}

func decodeEntry(domain string, qtype uint16, data []byte) (*Entry, bool) {
	if len(data) < 9 {
		return nil, false
	}
	var expiresAt time.Time
	var hitCount int64
	var lastHitAt time.Time
	var wireData []byte

	ver := data[0]
	switch ver {
	case valkeyValueVer2:
		if len(data) < 25 {
			return nil, false
		}
		nano := int64(binary.BigEndian.Uint64(data[1:9]))
		expiresAt = time.Unix(0, nano)
		hitCount = int64(binary.BigEndian.Uint64(data[9:17]))
		lhNano := int64(binary.BigEndian.Uint64(data[17:25]))
		if lhNano != 0 {
			lastHitAt = time.Unix(0, lhNano)
		}
		wireData = data[25:]
	case valkeyValueVer:
		nano := int64(binary.BigEndian.Uint64(data[1:9]))
		expiresAt = time.Unix(0, nano)
		wireData = data[9:]
	default:
		return nil, false
	}

	var msg dns.Message
	if err := msg.Parse(wireData); err != nil {
		slog.Error("bbolt decode parse error", "error", err)
		return nil, false
	}

	entry := &Entry{
		Domain:        domain,
		QType:         qtype,
		RCode:         msg.Header.Flags & 0x000F,
		AuthenticData: msg.Header.Flags&0x0020 != 0,
		Answers:       msg.Answers,
		Authorities:   msg.Authorities,
		Additionals:   msg.Additionals,
		ExpiresAt:     expiresAt,
	}
	entry.HitCount.Store(hitCount)
	if !lastHitAt.IsZero() {
		entry.SetLastHitAt(lastHitAt)
	}
	return entry, true
}

var _ Cache = (*Bbolt)(nil)
var _ Cache = (*Memory)(nil)
