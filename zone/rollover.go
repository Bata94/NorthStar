package zone

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"sync"
	"time"

	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
)

type RolloverPhase int

const (
	RolloverIdle       RolloverPhase = iota
	RolloverPublishing               // new DNSKEY published, still signing with old ZSK
	RolloverActive                   // signing with new ZSK, old DNSKEY still present
	RolloverCleanup                  // old DNSKEY removed
)

type ZoneRollover struct {
	mu        sync.Mutex
	zone      *Zone
	oldZSK    crypto.Signer
	oldTag    uint16
	newZSK    crypto.Signer
	newTag    uint16
	phase     RolloverPhase
	startTime time.Time
}

func (r *ZoneRollover) Phase() RolloverPhase {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.phase
}

func (r *ZoneRollover) OldZSK() crypto.Signer {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.phase == RolloverPublishing || r.phase == RolloverActive {
		return r.oldZSK
	}
	return nil
}

func (r *ZoneRollover) OldZSKTag() uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.oldTag
}

func (r *ZoneRollover) NewZSK() crypto.Signer {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.phase == RolloverPublishing || r.phase == RolloverActive {
		return r.newZSK
	}
	return nil
}

func (r *ZoneRollover) NewZSKTag() uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.newTag
}

func (r *ZoneRollover) SigningKey() crypto.Signer {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.phase {
	case RolloverPublishing:
		return r.oldZSK
	case RolloverActive, RolloverIdle:
		return r.zone.ZSKKey
	default:
		return r.zone.ZSKKey
	}
}

func (r *ZoneRollover) SigningTag() uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.phase {
	case RolloverPublishing:
		return r.oldTag
	case RolloverActive:
		return r.newTag
	default:
		return zskKeyTag(r.zone)
	}
}

func (r *ZoneRollover) OldDNSKEYRecord() *DNSKEYRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.oldZSK == nil {
		return nil
	}
	rec := BuildDNSKEYRecord(r.zone.Name, r.oldZSK, r.zone.DNSSEC.Algorithm, r.zone.SOA().TTLSec)
	if rec != nil {
		rec.Flags = 256
	}
	return rec
}

func ScheduleZSKRollover(zone *Zone, zskLifetimeDays, overlapDays, prePublishDays int) *ZoneRollover {
	rr := &ZoneRollover{
		zone:      zone,
		phase:     RolloverIdle,
		startTime: time.Now(),
	}
	go rr.runZSKRolloverLoop(zskLifetimeDays, overlapDays, prePublishDays)
	return rr
}

func (r *ZoneRollover) runZSKRolloverLoop(lifetimeDays, overlapDays, prePublishDays int) {
	if lifetimeDays <= 0 {
		lifetimeDays = 30
	}
	if overlapDays <= 0 {
		overlapDays = 7
	}
	if prePublishDays <= 0 {
		prePublishDays = 2
	}
	lifetime := time.Duration(lifetimeDays) * 24 * time.Hour
	overlap := time.Duration(overlapDays) * 24 * time.Hour
	prePub := time.Duration(prePublishDays) * 24 * time.Hour

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		r.mu.Lock()
		elapsed := time.Since(r.startTime)

		switch r.phase {
		case RolloverIdle:
			if elapsed >= lifetime-prePub {
				oldKey := r.zone.ZSKKey
				newKey, err := generateZSK(r.zone.DNSSEC.Algorithm)
				if err != nil {
					slog.Error("ZSK rollover: failed to generate new key", "zone", r.zone.Name, "error", err)
					r.mu.Unlock()
					continue
				}
				newTag := computeZSKTag(newKey, r.zone)
				r.oldZSK = oldKey
				r.oldTag = zskKeyTag(r.zone)
				r.newZSK = newKey
				r.newTag = newTag
				r.phase = RolloverPublishing
				slog.Info("ZSK rollover: publishing new key (pre-publish)", "zone", r.zone.Name, "newTag", newTag, "oldTag", r.oldTag)
			}

		case RolloverPublishing:
			if elapsed >= lifetime {
				r.zone.ZSKKey = r.newZSK
				r.phase = RolloverActive
				slog.Info("ZSK rollover: new key active", "zone", r.zone.Name, "tag", r.newTag)
			}

		case RolloverActive:
			if elapsed >= lifetime+overlap {
				r.phase = RolloverCleanup
				slog.Info("ZSK rollover: cleaning up old key", "zone", r.zone.Name, "oldTag", r.oldTag)
			}

		case RolloverCleanup:
			r.oldZSK = nil
			r.phase = RolloverIdle
			r.startTime = time.Now()
			slog.Info("ZSK rollover: cycle complete", "zone", r.zone.Name)
		}
		r.mu.Unlock()
	}
}

func generateZSK(algorithm uint8) (crypto.Signer, error) {
	switch algorithm {
	case dns.AlgECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case dns.AlgECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}

func computeZSKTag(key crypto.Signer, z *Zone) uint16 {
	pubWire, err := PublicKeyToWire(key.Public(), z.DNSSEC.Algorithm)
	if err != nil {
		return 0
	}
	return ComputeKeyTag(pubWire, z.DNSSEC.Algorithm, z.Name)
}

func zskKeyTag(z *Zone) uint16 {
	if z.ZSKKey == nil {
		return 0
	}
	return computeZSKTag(z.ZSKKey, z)
}

func BuildDNSKEYSet(zone *Zone, ksk crypto.Signer, zsk crypto.Signer) ([]Record, uint16, uint16) {
	kskRecord := BuildDNSKEYRecord(zone.Name, ksk, zone.DNSSEC.Algorithm, zone.SOA().TTLSec)
	kskRecord.Flags = 257
	kskWire, _ := kskRecord.RData()
	kskTag := ComputeKeyTag(kskWire, zone.DNSSEC.Algorithm, zone.Name)

	zskRecord := BuildDNSKEYRecord(zone.Name, zsk, zone.DNSSEC.Algorithm, zone.SOA().TTLSec)
	zskRecord.Flags = 256
	zskWire, _ := zskRecord.RData()
	zskTag := ComputeKeyTag(zskWire, zone.DNSSEC.Algorithm, zone.Name)

	return []Record{kskRecord, zskRecord}, kskTag, zskTag
}

func InitZoneRollover(zone *Zone, cfg *config.ZoneRolloverConfig) *ZoneRollover {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	zskLife := cfg.ZSKDays
	if zskLife <= 0 {
		zskLife = 30
	}
	overlap := cfg.Overlap
	if overlap <= 0 {
		overlap = 7
	}
	prePub := cfg.PrePublish
	if prePub <= 0 {
		prePub = 2
	}

	if zone.ZSKKey == zone.SigningKey {
		newZSK, err := generateZSK(zone.DNSSEC.Algorithm)
		if err == nil {
			zone.ZSKKey = newZSK
			slog.Info("Generated initial ZSK for zone", "zone", zone.Name)
		}
	}

	return ScheduleZSKRollover(zone, zskLife, overlap, prePub)
}
