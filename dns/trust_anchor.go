package dns

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

type TrustAnchorState int

const (
	AnchorStateStart   TrustAnchorState = iota
	AnchorStateAppear                   // key seen but not yet accepted (RFC 5011 add hold-down)
	AnchorStateValid                    // key is a valid trust anchor
	AnchorStateRevoked                  // key revoked (RFC 5011 remove hold-down)
	AnchorStateRemoved                  // key removed
)

type TrackedKey struct {
	DNSKEY    DNSKEY
	State     TrustAnchorState
	FirstSeen time.Time
	AddTimer  time.Time
}

type TrustAnchorStore struct {
	mu          sync.RWMutex
	anchors     map[uint16]*TrackedKey
	ownerNames  map[uint16]string
	addHoldDown time.Duration
	revHoldDown time.Duration
}

func NewTrustAnchorStore(addHoldDown, revHoldDown time.Duration) *TrustAnchorStore {
	if addHoldDown < 0 {
		addHoldDown = 0
	}
	if addHoldDown == 0 {
		addHoldDown = 1
	}
	if revHoldDown < 0 {
		revHoldDown = 0
	}
	if revHoldDown == 0 {
		revHoldDown = 1
	}
	return &TrustAnchorStore{
		anchors:     make(map[uint16]*TrackedKey),
		ownerNames:  make(map[uint16]string),
		addHoldDown: addHoldDown,
		revHoldDown: revHoldDown,
	}
}

func (s *TrustAnchorStore) AddInitial(dnskey DNSKEY, owner string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keyTag := DNSKEYKeyTag(owner, dnskey.PublicKey, dnskey.Algorithm)
	s.anchors[keyTag] = &TrackedKey{
		DNSKEY:    dnskey,
		State:     AnchorStateValid,
		FirstSeen: time.Now(),
	}
	s.ownerNames[keyTag] = owner
}

func (s *TrustAnchorStore) Observe(dnskey DNSKEY, owner string) (trusted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keyTag := DNSKEYKeyTag(owner, dnskey.PublicKey, dnskey.Algorithm)
	tk, exists := s.anchors[keyTag]

	if !exists {
		s.anchors[keyTag] = &TrackedKey{
			DNSKEY:    dnskey,
			State:     AnchorStateAppear,
			FirstSeen: time.Now(),
			AddTimer:  time.Now().Add(s.addHoldDown),
		}
		s.ownerNames[keyTag] = owner
		return false
	}

	switch tk.State {
	case AnchorStateAppear:
		if time.Now().After(tk.AddTimer) {
			tk.State = AnchorStateValid
			tk.DNSKEY = dnskey
			return true
		}
		return false

	case AnchorStateValid:
		tk.DNSKEY = dnskey
		if dnskey.Flags&0x0080 != 0 {
			tk.State = AnchorStateRevoked
			tk.AddTimer = time.Now().Add(s.revHoldDown)
		}
		return true

	case AnchorStateRevoked:
		if time.Now().After(tk.AddTimer) {
			tk.State = AnchorStateRemoved
			delete(s.anchors, keyTag)
			delete(s.ownerNames, keyTag)
		}
		return false
	}

	return false
}

func (s *TrustAnchorStore) IsTrusted(keyTag uint16) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tk, ok := s.anchors[keyTag]
	return ok && tk.State == AnchorStateValid
}

func (s *TrustAnchorStore) Get(keyTag uint16) *TrackedKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tk, ok := s.anchors[keyTag]
	if !ok {
		return nil
	}
	cp := *tk
	return &cp
}

func (s *TrustAnchorStore) GetValid() []DNSKEY {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []DNSKEY
	for _, tk := range s.anchors {
		if tk.State == AnchorStateValid {
			out = append(out, tk.DNSKEY)
		}
	}
	return out
}

func (s *TrustAnchorStore) Tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for keyTag, tk := range s.anchors {
		switch tk.State {
		case AnchorStateAppear:
			if time.Now().After(tk.AddTimer) {
				tk.State = AnchorStateValid
			}
		case AnchorStateRevoked:
			if time.Now().After(tk.AddTimer) {
				tk.State = AnchorStateRemoved
				delete(s.anchors, keyTag)
				delete(s.ownerNames, keyTag)
			}
		}
	}
}

func (s *TrustAnchorStore) Owner(keyTag uint16) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ownerNames[keyTag]
}

func ParseTrustAnchorFile(path string) ([]struct {
	DNSKEY DNSKEY
	Owner  string
}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			slog.Error("failed to close trust anchor file", "path", path, "error", err)
		}
	}()

	var entries []struct {
		DNSKEY DNSKEY
		Owner  string
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 7 {
			continue
		}
		if strings.ToUpper(parts[3]) != "DNSKEY" {
			continue
		}
		dnskey, owner, err := parseTrustAnchorLine(parts)
		if err != nil {
			continue
		}
		entries = append(entries, struct {
			DNSKEY DNSKEY
			Owner  string
		}{DNSKEY: *dnskey, Owner: owner})
	}
	return entries, scanner.Err()
}

func parseTrustAnchorLine(parts []string) (*DNSKEY, string, error) {
	if len(parts) < 7 {
		return nil, "", errors.New("dns: too few fields in trust anchor entry")
	}
	owner := parts[0]
	algorithm := uint8(0)
	flags := uint16(0)
	protocol := uint8(3)

	if _, err := fmt.Sscanf(parts[4], "%d", &flags); err != nil {
		return nil, "", fmt.Errorf("dns: invalid flags in trust anchor entry: %w", err)
	}
	if _, err := fmt.Sscanf(parts[5], "%d", &protocol); err != nil {
		return nil, "", fmt.Errorf("dns: invalid protocol in trust anchor entry: %w", err)
	}
	if _, err := fmt.Sscanf(parts[6], "%d", &algorithm); err != nil {
		return nil, "", fmt.Errorf("dns: invalid algorithm in trust anchor entry: %w", err)
	}

	pubKeyStr := strings.Join(parts[7:], "")
	pubKey := []byte(pubKeyStr)

	return &DNSKEY{
		Flags:     flags,
		Protocol:  protocol,
		Algorithm: algorithm,
		PublicKey: pubKey,
	}, owner, nil
}

func VerifyChain(store *TrustAnchorStore, dsRecords []*DS, dnskey *DNSKEY, owner string) bool {
	if store == nil {
		return true
	}
	keyTag := DNSKEYKeyTag(owner, dnskey.PublicKey, dnskey.Algorithm)
	if store.IsTrusted(keyTag) {
		return true
	}
	for _, ds := range dsRecords {
		if err := VerifyDS(ds, dnskey, owner); err == nil {
			return true
		}
	}
	return false
}

func (s *TrustAnchorStore) LoadFile(path string) error {
	entries, err := ParseTrustAnchorFile(path)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("dns: no trust anchors found in file")
	}
	for _, e := range entries {
		s.AddInitial(e.DNSKEY, e.Owner)
	}
	return nil
}
