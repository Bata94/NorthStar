// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package cache

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"time"

	"github.com/bata94/northstar/dns"
	"github.com/valkey-io/valkey-go"
)

const valkeyValueVer byte = 0x01

type Valkey struct {
	client   valkey.Client
	staleAge time.Duration
}

func NewValkey(addr string, staleAge int) (*Valkey, error) {
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{addr},
	})
	if err != nil {
		return nil, fmt.Errorf("valkey new client: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Do(pingCtx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("valkey ping: %w", err)
	}

	return &Valkey{client: client, staleAge: time.Duration(staleAge) * time.Second}, nil
}

func (v *Valkey) Get(ctx context.Context, domain string, qtype uint16) (*Entry, bool) {
	key := v.key(domain, qtype)

	data, err := v.client.Do(ctx, v.client.B().Get().Key(key).Build()).AsBytes()
	if err != nil {
		if !valkey.IsValkeyNil(err) {
			slog.Error("Valkey get error", "error", err)
		}
		return nil, false
	}

	var expiresAt time.Time
	var wireData []byte

	if len(data) > 0 && data[0] == valkeyValueVer && len(data) >= 9 {
		nano := int64(binary.BigEndian.Uint64(data[1:9]))
		expiresAt = time.Unix(0, nano)
		wireData = data[9:]
	} else {
		remaining, err := v.client.Do(ctx, v.client.B().Ttl().Key(key).Build()).AsInt64()
		if err != nil || remaining <= 0 {
			return nil, false
		}
		expiresAt = time.Now().Add(time.Duration(remaining) * time.Second)
		wireData = data
	}

	var msg dns.Message
	if err := msg.Parse(wireData); err != nil {
		slog.Error("Valkey parse error", "error", err)
		return nil, false
	}

	return &Entry{
		Domain:        domain,
		QType:         qtype,
		RCode:         msg.Header.Flags & 0x000F,
		AuthenticData: msg.Header.Flags&0x0020 != 0,
		Answers:       msg.Answers,
		Authorities:   msg.Authorities,
		Additionals:   msg.Additionals,
		ExpiresAt:     expiresAt,
	}, true
}

func (v *Valkey) Peek(ctx context.Context, domain string, qtype uint16) (*Entry, bool) {
	return v.Get(ctx, domain, qtype)
}

func (v *Valkey) Set(ctx context.Context, entry *Entry) error {
	remaining := time.Until(entry.ExpiresAt)
	ttl := remaining + v.staleAge
	if ttl <= 0 {
		return nil
	}

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

	buf := make([]byte, 1+8+len(wireData))
	buf[0] = valkeyValueVer
	binary.BigEndian.PutUint64(buf[1:9], uint64(entry.ExpiresAt.UnixNano()))
	copy(buf[9:], wireData)

	key := v.key(entry.Domain, entry.QType)
	if err := v.client.Do(ctx, v.client.B().Set().Key(key).Value(string(buf)).ExSeconds(int64(ttl.Seconds())).Build()).Error(); err != nil {
		return err
	}
	return nil
}

func (v *Valkey) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	val, err := v.client.Do(ctx, v.client.B().Incr().Key(key).Build()).AsInt64()
	if err != nil {
		return 0, err
	}
	if err := v.client.Do(ctx, v.client.B().Expire().Key(key).Seconds(int64(ttl.Seconds())).Build()).Error(); err != nil {
		return 0, err
	}
	return val, nil
}

func (v *Valkey) Close() {
	v.client.Close()
}

func (v *Valkey) key(domain string, qtype uint16) string {
	return fmt.Sprintf("northstar:%s:%d", domain, qtype)
}
