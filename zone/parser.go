package zone

import (
	"crypto"
	"fmt"
	"net"
	"strings"

	"github.com/bata94/northstar/config"
)

func ParseZoneConfig(cfg config.ZoneConfig) (*Zone, error) {
	name := cfg.Name
	if name == "" {
		return nil, fmt.Errorf("zone name is required")
	}
	if name[len(name)-1] != '.' {
		name += "."
	}

	var records []Record
	for _, rc := range cfg.Records {
		recs, err := parseRecordConfig(rc, name)
		if err != nil {
			return nil, fmt.Errorf("zone %q record %q: %w", cfg.Name, rc.Type, err)
		}
		records = append(records, recs...)
	}

	var views []*ZoneView
	for _, vc := range cfg.Views {
		viewName := vc.Name
		var subnet *net.IPNet
		if vc.Subnet != "" {
			_, parsed, err := net.ParseCIDR(vc.Subnet)
			if err != nil {
				return nil, fmt.Errorf("zone %q view %q: invalid subnet %q: %w", cfg.Name, viewName, vc.Subnet, err)
			}
			subnet = parsed
		}
		var viewRecords []Record
		for _, rc := range vc.Records {
			recs, err := parseRecordConfig(rc, name)
			if err != nil {
				return nil, fmt.Errorf("zone %q view %q record %q: %w", cfg.Name, viewName, rc.Type, err)
			}
			viewRecords = append(viewRecords, recs...)
		}
		views = append(views, NewZoneView(viewName, subnet, viewRecords))
	}

	var dnssec *DNSSECConfig
	var signingKey crypto.Signer
	var zskKey crypto.Signer
	if cfg.DNSSEC != nil && cfg.DNSSEC.Enabled {
		alg := algorithmFromString(cfg.DNSSEC.Algorithm)
		nsec3Enabled := cfg.DNSSEC.NSEC3 != nil && cfg.DNSSEC.NSEC3.Enabled
		dnssec = &DNSSECConfig{
			Enabled:   cfg.DNSSEC.Enabled,
			Algorithm: alg,
			KeyFile:   cfg.DNSSEC.KeyFile,
			ZSKFile:   cfg.DNSSEC.ZSKFile,
			NSEC3:     nsec3Enabled,
		}
		if cfg.DNSSEC.KeyFile != "" {
			var lerr error
			signingKey, lerr = LoadKey(cfg.DNSSEC.KeyFile)
			if lerr != nil {
				return nil, fmt.Errorf("load KSK for zone %q: %w", cfg.Name, lerr)
			}
		} else {
			var gerr error
			signingKey, gerr = GenerateKey("", alg)
			if gerr != nil {
				return nil, fmt.Errorf("generate KSK for zone %q: %w", cfg.Name, gerr)
			}
		}
		if cfg.DNSSEC.ZSKFile != "" {
			var lerr error
			zskKey, lerr = LoadKey(cfg.DNSSEC.ZSKFile)
			if lerr != nil {
				return nil, fmt.Errorf("load ZSK for zone %q: %w", cfg.Name, lerr)
			}
		} else {
			zskKey = signingKey
		}
	}

	return New(name, records, dnssec, signingKey, zskKey, views), nil
}

func parseRecordConfig(rc config.ZoneRecordConfig, zone string) ([]Record, error) {
	owner := expandName(rc.Name, zone)
	ttl := rc.TTL
	if ttl == 0 {
		ttl = 3600
	}

	switch strings.ToUpper(rc.Type) {
	case "A":
		if rc.IP == nil {
			return nil, fmt.Errorf("a record requires ip field")
		}
		ip := net.ParseIP(*rc.IP)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %s", *rc.IP)
		}
		return []Record{&ARecord{Name: owner, TTLSec: ttl, IP: ip}}, nil

	case "AAAA":
		if rc.IP == nil {
			return nil, fmt.Errorf("aaaa record requires ip field")
		}
		ip := net.ParseIP(*rc.IP)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %s", *rc.IP)
		}
		return []Record{&AAAARecord{Name: owner, TTLSec: ttl, IP: ip}}, nil

	case "CNAME":
		if rc.Target == nil {
			return nil, fmt.Errorf("cname record requires target field")
		}
		target := *rc.Target
		if target[len(target)-1] != '.' {
			target += "."
		}
		return []Record{&CNAMERecord{Name: owner, TTLSec: ttl, Target: target}}, nil

	case "NS":
		if rc.Target == nil {
			return nil, fmt.Errorf("ns record requires target field")
		}
		target := *rc.Target
		if target[len(target)-1] != '.' {
			target += "."
		}
		return []Record{&NSRecord{Name: owner, TTLSec: ttl, Target: target}}, nil

	case "MX":
		if rc.Preference == nil || rc.Host == nil {
			return nil, fmt.Errorf("mx record requires preference and host fields")
		}
		host := *rc.Host
		if host[len(host)-1] != '.' {
			host += "."
		}
		return []Record{&MXRecord{Name: owner, TTLSec: ttl, Preference: *rc.Preference, Host: host}}, nil

	case "SOA":
		if rc.MName == nil || rc.RName == nil {
			return nil, fmt.Errorf("soa record requires mname and rname fields")
		}
		mname := *rc.MName
		rname := *rc.RName
		if mname[len(mname)-1] != '.' {
			mname += "."
		}
		if rname[len(rname)-1] != '.' {
			rname += "."
		}
		var serial, refresh, retry, expire, minimum uint32
		if rc.Serial != nil {
			serial = *rc.Serial
		}
		if rc.Refresh != nil {
			refresh = *rc.Refresh
		} else {
			refresh = 3600
		}
		if rc.Retry != nil {
			retry = *rc.Retry
		} else {
			retry = 900
		}
		if rc.Expire != nil {
			expire = *rc.Expire
		} else {
			expire = 86400
		}
		if rc.Minimum != nil {
			minimum = *rc.Minimum
		} else {
			minimum = 3600
		}
		return []Record{&SOARecord{
			Name: owner, TTLSec: ttl,
			MName: mname, RName: rname,
			Serial: serial, Refresh: refresh,
			Retry: retry, Expire: expire, Minimum: minimum,
		}}, nil

	case "TXT":
		if rc.TXTData == nil {
			return nil, fmt.Errorf("txt record requires txt_data field")
		}
		return []Record{&TXTRecord{Name: owner, TTLSec: ttl, Data: *rc.TXTData}}, nil

	case "SRV":
		if rc.SRVPriority == nil || rc.SRVWeight == nil || rc.SRVPort == nil || rc.SRVTarget == nil {
			return nil, fmt.Errorf("srv record requires srv_priority, srv_weight, srv_port, srv_target fields")
		}
		target := *rc.SRVTarget
		if target[len(target)-1] != '.' {
			target += "."
		}
		return []Record{&SRVRecord{
			Name: owner, TTLSec: ttl,
			Priority: *rc.SRVPriority, Weight: *rc.SRVWeight,
			Port: *rc.SRVPort, Target: target,
		}}, nil

	case "DNSKEY":
		if rc.DNSKEYFlags == nil || rc.DNSKEYAlgorithm == nil || rc.DNSKEYPublicKey == nil {
			return nil, fmt.Errorf("dnskey record requires dnskey_flags, dnskey_algorithm, dnskey_public_key fields")
		}
		return []Record{&DNSKEYRecord{
			Name: owner, TTLSec: ttl,
			Flags: *rc.DNSKEYFlags, Protocol: 3,
			Algorithm: *rc.DNSKEYAlgorithm,
			PublicKey: []byte(*rc.DNSKEYPublicKey),
		}}, nil

	case "NSEC3":
		if rc.NSECNextDomain == nil || rc.NSECTypes == nil {
			return nil, fmt.Errorf("nsec3 record requires nsec_next_domain and nsec_types fields")
		}
		nextDomain := *rc.NSECNextDomain
		if nextDomain[len(nextDomain)-1] != '.' {
			nextDomain += "."
		}
		return []Record{&NSEC3Record{
			Name:            owner,
			TTLSec:          ttl,
			HashAlgorithm:   1,
			Flags:           0,
			Iterations:      0,
			Salt:            nil,
			NextHashedOwner: []byte(nextDomain),
			Types:           *rc.NSECTypes,
		}}, nil

	case "RRSIG":
		if rc.RRSIGTypeCovered == nil || rc.RRSIGAlgorithm == nil || rc.RRSIGLabels == nil ||
			rc.RRSIGOriginalTTL == nil || rc.RRSIGExpiration == nil || rc.RRSIGInception == nil ||
			rc.RRSIGKeyTag == nil || rc.RRSIGSignerName == nil || rc.RRSIGSignature == nil {
			return nil, fmt.Errorf("rrsig record requires all rrsig_* fields")
		}
		signer := *rc.RRSIGSignerName
		if signer[len(signer)-1] != '.' {
			signer += "."
		}
		return []Record{&RRSIGRecord{
			Name: owner, TTLSec: ttl,
			TypeCovered:   *rc.RRSIGTypeCovered,
			Algorithm:     *rc.RRSIGAlgorithm,
			Labels:        *rc.RRSIGLabels,
			OriginalTTL:   *rc.RRSIGOriginalTTL,
			SigExpiration: *rc.RRSIGExpiration,
			SigInception:  *rc.RRSIGInception,
			KeyTag:        *rc.RRSIGKeyTag,
			SignerName:    signer,
			Signature:     []byte(*rc.RRSIGSignature),
		}}, nil

	case "NSEC":
		if rc.NSECNextDomain == nil || rc.NSECTypes == nil {
			return nil, fmt.Errorf("nsec record requires nsec_next_domain and nsec_types fields")
		}
		next := *rc.NSECNextDomain
		if next[len(next)-1] != '.' {
			next += "."
		}
		return []Record{&NSECRecord{
			Name: owner, TTLSec: ttl,
			NextDomain: next,
			Types:      *rc.NSECTypes,
		}}, nil

	default:
		return nil, fmt.Errorf("unsupported record type: %s", rc.Type)
	}
}

func ZoneConfigFromZone(z *Zone) config.ZoneConfig {
	cfg := config.ZoneConfig{Name: z.Name}
	for _, r := range z.Records {
		cfg.Records = append(cfg.Records, recordConfigFromRecord(r))
	}
	if z.DNSSEC != nil && z.DNSSEC.Enabled {
		alg := algorithmString(z.DNSSEC.Algorithm)
		zc := &config.ZoneDNSSECConfig{
			Enabled:   true,
			Algorithm: alg,
			KeyFile:   z.DNSSEC.KeyFile,
			ZSKFile:   z.DNSSEC.ZSKFile,
		}
		if z.DNSSEC.NSEC3 {
			zc.NSEC3 = &config.ZoneNSEC3Config{Enabled: true}
		}
		cfg.DNSSEC = zc
	}
	return cfg
}

func recordConfigFromRecord(r Record) config.ZoneRecordConfig {
	c := config.ZoneRecordConfig{}
	owner := trimDot(r.DNSName())

	switch v := r.(type) {
	case *ARecord:
		c.Name = owner
		c.Type = "A"
		c.TTL = v.TTLSec
		ip := v.IP.String()
		c.IP = &ip
	case *AAAARecord:
		c.Name = owner
		c.Type = "AAAA"
		c.TTL = v.TTLSec
		ip := v.IP.String()
		c.IP = &ip
	case *CNAMERecord:
		c.Name = owner
		c.Type = "CNAME"
		c.TTL = v.TTLSec
		t := trimDot(v.Target)
		c.Target = &t
	case *NSRecord:
		c.Name = owner
		c.Type = "NS"
		c.TTL = v.TTLSec
		t := trimDot(v.Target)
		c.Target = &t
	case *MXRecord:
		c.Name = owner
		c.Type = "MX"
		c.TTL = v.TTLSec
		c.Preference = &v.Preference
		h := trimDot(v.Host)
		c.Host = &h
	case *SOARecord:
		c.Name = owner
		c.Type = "SOA"
		c.TTL = v.TTLSec
		m := trimDot(v.MName)
		r := trimDot(v.RName)
		c.MName = &m
		c.RName = &r
		c.Serial = &v.Serial
		c.Refresh = &v.Refresh
		c.Retry = &v.Retry
		c.Expire = &v.Expire
		c.Minimum = &v.Minimum
	case *TXTRecord:
		c.Name = owner
		c.Type = "TXT"
		c.TTL = v.TTLSec
		c.TXTData = &v.Data
	case *SRVRecord:
		c.Name = owner
		c.Type = "SRV"
		c.TTL = v.TTLSec
		c.SRVPriority = &v.Priority
		c.SRVWeight = &v.Weight
		c.SRVPort = &v.Port
		t := trimDot(v.Target)
		c.SRVTarget = &t
	case *DNSKEYRecord:
		c.Name = owner
		c.Type = "DNSKEY"
		c.TTL = v.TTLSec
		c.DNSKEYFlags = &v.Flags
		c.DNSKEYAlgorithm = &v.Algorithm
		pk := string(v.PublicKey)
		c.DNSKEYPublicKey = &pk
	case *RRSIGRecord:
		c.Name = owner
		c.Type = "RRSIG"
		c.TTL = v.TTLSec
		c.RRSIGTypeCovered = &v.TypeCovered
		c.RRSIGAlgorithm = &v.Algorithm
		c.RRSIGLabels = &v.Labels
		c.RRSIGOriginalTTL = &v.OriginalTTL
		c.RRSIGExpiration = &v.SigExpiration
		c.RRSIGInception = &v.SigInception
		c.RRSIGKeyTag = &v.KeyTag
		s := trimDot(v.SignerName)
		c.RRSIGSignerName = &s
		sig := string(v.Signature)
		c.RRSIGSignature = &sig
	case *NSECRecord:
		c.Name = owner
		c.Type = "NSEC"
		c.TTL = v.TTLSec
		nd := trimDot(v.NextDomain)
		c.NSECNextDomain = &nd
		c.NSECTypes = &v.Types
	}
	return c
}
