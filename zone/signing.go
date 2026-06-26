package zone

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/bata94/northstar/dns"
)

func GenerateKey(path string, algorithm uint8) (crypto.Signer, error) {
	var key crypto.Signer
	switch algorithm {
	case dns.AlgECDSAP256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ecdsa p256 key: %w", err)
		}
		key = k
	case dns.AlgECDSAP384:
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ecdsa p384 key: %w", err)
		}
		key = k
	default:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ecdsa p256 key: %w", err)
		}
		key = k
	}

	if path != "" {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshal private key: %w", err)
		}
		block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			return nil, fmt.Errorf("write key file: %w", err)
		}
	}
	return key, nil
}

func LoadKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM data in key file")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("key does not implement crypto.Signer")
	}
	return signer, nil
}

func PublicKeyToWire(pub crypto.PublicKey, algorithm uint8) ([]byte, error) {
	switch algorithm {
	case dns.AlgECDSAP256, dns.AlgECDSAP384:
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("not an ECDSA key")
		}
		ecdhKey, err := ecKey.ECDH()
		if err != nil {
			return nil, fmt.Errorf("ecdh: %w", err)
		}
		curveSize := (ecKey.Curve.Params().BitSize + 7) / 8
		raw := ecdhKey.Bytes()
		if len(raw) != 2*curveSize+1 {
			return nil, fmt.Errorf("unexpected public key length: %d", len(raw))
		}
		return raw[1:], nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}
}

type Ed25519PublicKey []byte

func ComputeKeyTag(pubKey []byte, algorithm uint8, zoneName string) uint16 {
	owner := trimDot(zoneName)
	var buf []byte
	for _, label := range splitLabels2(owner) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0)
	buf = binary.BigEndian.AppendUint16(buf, 256)
	buf = append(buf, 0)
	buf = append(buf, algorithm)
	buf = append(buf, pubKey...)

	var ac uint32
	for i := 0; i < len(buf); i++ {
		if i&1 == 0 {
			ac += uint32(buf[i]) << 8
		} else {
			ac += uint32(buf[i])
		}
	}
	ac += ac >> 16
	return uint16(ac & 0xFFFF)
}

func countLabels(name string) uint8 {
	n := trimDot(name)
	if n == "" {
		return 0
	}
	labels := splitLabels2(n)
	if len(labels) > 128 {
		return 128
	}
	return uint8(len(labels))
}

func SignRRset(records []Record, zoneName string, key crypto.Signer, algorithm uint8, dnskeyTag uint16) (*RRSIGRecord, error) {
	if len(records) == 0 {
		return nil, errors.New("no records to sign")
	}

	signerName := zoneName
	now := time.Now()
	inception := uint32(now.Unix()) - 3600
	expiration := uint32(now.Unix()) + 7*86400

	rrType := records[0].DNSType()
	ttl := records[0].TTL()
	name := records[0].DNSName()
	labels := countLabels(name)

	var rrset []dns.ResourceRecord
	for _, r := range records {
		rrset = append(rrset, recordToRR(r))
	}

	rrsigHeader := make([]byte, 18)
	binary.BigEndian.PutUint16(rrsigHeader[0:2], rrType)
	rrsigHeader[2] = algorithm
	rrsigHeader[3] = labels
	binary.BigEndian.PutUint32(rrsigHeader[4:8], ttl)
	binary.BigEndian.PutUint32(rrsigHeader[8:12], expiration)
	binary.BigEndian.PutUint32(rrsigHeader[12:16], inception)
	binary.BigEndian.PutUint16(rrsigHeader[16:18], dnskeyTag)

	// Build full rrsig data with signer name for wire form
	fullRRSIGData := append(rrsigHeader, EncodeName(signerName)...)
	wireForm, err := buildRRSIGWire(rrset, fullRRSIGData)
	if err != nil {
		return nil, fmt.Errorf("build rrsig wire: %w", err)
	}

	var sig []byte
	if algorithm == dns.AlgECDSAP256 || algorithm == dns.AlgECDSAP384 {
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if ok {
			hasher := crypto.SHA256.New()
			if algorithm == dns.AlgECDSAP384 {
				hasher = crypto.SHA384.New()
			}
			hasher.Write(wireForm)
			digest := hasher.Sum(nil)
			sig, err = ecdsa.SignASN1(rand.Reader, ecKey, digest)
			if err != nil {
				return nil, fmt.Errorf("sign rrsig: %w", err)
			}
			sig = ecdsaSigToRSSig(sig, algorithm)
		} else {
			sig, err = key.Sign(rand.Reader, wireForm, crypto.SHA256)
			if err != nil {
				return nil, fmt.Errorf("sign rrsig: %w", err)
			}
			if algorithm == dns.AlgECDSAP256 || algorithm == dns.AlgECDSAP384 {
				sig = ecdsaSigToRSSig(sig, algorithm)
			}
		}
	} else {
		sig, err = key.Sign(rand.Reader, wireForm, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("sign rrsig: %w", err)
		}
	}

	return &RRSIGRecord{
		Name:          name,
		TTLSec:        ttl,
		TypeCovered:   rrType,
		Algorithm:     algorithm,
		Labels:        labels,
		OriginalTTL:   ttl,
		SigExpiration: expiration,
		SigInception:  inception,
		KeyTag:        dnskeyTag,
		SignerName:    signerName,
		Signature:     sig,
	}, nil
}

func ecdsaSigToRSSig(sig []byte, algorithm uint8) []byte {
	if len(sig) < 2 {
		return sig
	}
	// Try to parse DER-encoded signature
	r, s := parseECDSASig(sig)
	var curveSize int
	if algorithm == dns.AlgECDSAP256 {
		curveSize = 32
	} else {
		curveSize = 48
	}
	out := make([]byte, 2*curveSize)
	r.FillBytes(out[:curveSize])
	s.FillBytes(out[curveSize:])
	return out
}

func parseECDSASig(sig []byte) (*big.Int, *big.Int) {
	// Try to parse hex DER
	if len(sig) > 2 && sig[0] == 0x30 {
		// DER sequence
		data := sig
		if int(data[1])+2 <= len(data) {
			data = data[2:]
		}
		r := new(big.Int)
		s := new(big.Int)
		if len(data) > 2 && data[0] == 0x02 {
			rLen := int(data[1])
			if 2+rLen <= len(data) {
				r.SetBytes(data[2 : 2+rLen])
				data = data[2+rLen:]
			}
		}
		if len(data) > 2 && data[0] == 0x02 {
			sLen := int(data[1])
			if 2+sLen <= len(data) {
				s.SetBytes(data[2 : 2+sLen])
			}
		}
		return r, s
	}
	// Raw r||s
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	return r, s
}

func BuildDNSKEYRecord(name string, key crypto.Signer, algorithm uint8, ttl uint32) *DNSKEYRecord {
	pub := key.Public()
	pubKey, err := PublicKeyToWire(pub, algorithm)
	if err != nil {
		return nil
	}

	flags := uint16(256)
	if algorithm == dns.AlgECDSAP256 {
		flags = 256
	}

	return &DNSKEYRecord{
		Name:      name,
		TTLSec:    ttl,
		Flags:     flags,
		Protocol:  3,
		Algorithm: algorithm,
		PublicKey: pubKey,
	}
}

// NSEC3Hash computes the salted, iterated SHA-1 hash of a domain name
// per RFC 5155 §5.
func NSEC3Hash(name string, salt []byte, iterations uint16) ([]byte, error) {
	// Canonical wire form: lowercased, uncompressed labels (RFC 5155 §5)
	wire := EncodeName(strings.ToLower(name))
	h := sha1.New()
	h.Write(wire)
	if len(salt) > 0 {
		h.Write(salt)
	}
	prev := h.Sum(nil)
	for i := uint16(0); i < iterations; i++ {
		h.Reset()
		h.Write(prev)
		if len(salt) > 0 {
			h.Write(salt)
		}
		prev = h.Sum(nil)
	}
	return prev, nil
}

// Base32HexEncode encodes bytes to lowercase base32hex (RFC 4648 §7, no padding).
func Base32HexEncode(data []byte) string {
	const enc = "0123456789abcdefghijklmnopqrstuv"
	var out []byte
	bits := 0
	val := 0
	for _, b := range data {
		val = (val << 8) | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, enc[(val>>bits)&0x1F])
		}
	}
	if bits > 0 {
		out = append(out, enc[(val<<(5-bits))&0x1F])
	}
	return string(out)
}

// Base32HexDecode decodes lowercase base32hex (RFC 4648 §7, no padding).
func Base32HexDecode(s string) ([]byte, error) {
	var out []byte
	bits := 0
	val := 0
	for _, c := range []byte(s) {
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'a' && c <= 'v':
			v = int(c - 'a' + 10)
		case c >= 'A' && c <= 'V':
			v = int(c - 'A' + 10)
		default:
			return nil, fmt.Errorf("invalid base32hex char: %c", c)
		}
		val = (val << 5) | v
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(val>>bits))
			val &= (1 << bits) - 1
		}
	}
	return out, nil
}

// BuildNSEC3Chain builds an NSEC3 chain for the zone.
// The salt is hex-decoded from the config; pass the raw bytes.
func BuildNSEC3Chain(zone *Zone, iterations uint16, salt []byte, optOut bool) []*NSEC3Record {
	if len(zone.byName) == 0 {
		return nil
	}
	type hashEntry struct {
		hash  []byte
		name  string
		types []uint16
	}
	var entries []hashEntry
	for name, records := range zone.byName {
		if name == zone.Name {
			continue
		}
		h, err := NSEC3Hash(name, salt, iterations)
		if err != nil {
			continue
		}
		typeSet := make(map[uint16]bool)
		for _, r := range records {
			t := r.DNSType()
			if t == dns.TypeNSEC3 || t == dns.TypeNSEC3PARAM || t == dns.TypeRRSIG {
				continue
			}
			typeSet[t] = true
		}
		var types []uint16
		for t := range typeSet {
			types = append(types, t)
		}
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
		entries = append(entries, hashEntry{hash: h, name: name, types: types})
	}
	// Also hash the zone apex name
	apexHash, err := NSEC3Hash(zone.Name, salt, iterations)
	if err == nil {
		apexTypes := make(map[uint16]bool)
		for _, r := range zone.byName[zone.Name] {
			t := r.DNSType()
			if t == dns.TypeNSEC3 || t == dns.TypeNSEC3PARAM || t == dns.TypeRRSIG {
				continue
			}
			apexTypes[t] = true
		}
		var types []uint16
		for t := range apexTypes {
			types = append(types, t)
		}
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
		entries = append(entries, hashEntry{hash: apexHash, name: zone.Name, types: types})
	}
	if len(entries) == 0 {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool {
		return compareHashes(entries[i].hash, entries[j].hash) < 0
	})
	flags := uint8(0)
	if optOut {
		flags |= 0x01
	}
	var chain []*NSEC3Record
	for i, entry := range entries {
		nextHash := entries[0].hash
		if i+1 < len(entries) {
			nextHash = entries[i+1].hash
		}
		encodedName := Base32HexEncode(entry.hash) + "." + zone.Name
		chain = append(chain, &NSEC3Record{
			Name:            encodedName,
			TTLSec:          zone.SOA().TTLSec,
			HashAlgorithm:   1,
			Flags:           flags,
			Iterations:      iterations,
			Salt:            salt,
			NextHashedOwner: nextHash,
			Types:           entry.types,
		})
	}
	return chain
}

func compareHashes(a, b []byte) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// BuildNSEC3PARAMRecord creates the NSEC3PARAM record for the zone apex.
func BuildNSEC3PARAMRecord(zone *Zone, iterations uint16, salt []byte) *NSEC3PARAMRecord {
	return &NSEC3PARAMRecord{
		Name:       zone.Name,
		TTLSec:     zone.SOA().TTLSec,
		Hash:       1,
		Flags:      0,
		Iterations: iterations,
		Salt:       salt,
	}
}

func BuildNSECChain(zone *Zone) []*NSECRecord {
	if len(zone.byName) == 0 {
		return nil
	}

	var names []string
	for name := range zone.byName {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return canonicalCompare(names[i], names[j]) < 0
	})

	var chain []*NSECRecord
	for i, name := range names {
		nextName := names[0]
		if i+1 < len(names) {
			nextName = names[i+1]
		}

		var types []uint16
		typeSet := make(map[uint16]bool)
		for _, r := range zone.byName[name] {
			t := r.DNSType()
			if !typeSet[t] {
				types = append(types, t)
				typeSet[t] = true
			}
		}
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

		chain = append(chain, &NSECRecord{
			Name:       name,
			TTLSec:     zone.SOA().TTLSec,
			NextDomain: nextName,
			Types:      types,
		})
	}
	return chain
}

func canonicalCompare(a, b string) int {
	a = trimDot(a)
	b = trimDot(b)
	aLabels := splitLabels2(a)
	bLabels := splitLabels2(b)
	i, j := len(aLabels)-1, len(bLabels)-1
	for i >= 0 && j >= 0 {
		if aLabels[i] != bLabels[j] {
			if aLabels[i] < bLabels[j] {
				return -1
			}
			return 1
		}
		i--
		j--
	}
	if i >= 0 {
		return 1
	}
	if j >= 0 {
		return -1
	}
	return 0
}

func AttachDNSSEC(zone *Zone, resp *dns.Message, req *dns.Message, key crypto.Signer) *dns.Message {
	if zone.DNSSEC == nil || !zone.DNSSEC.Enabled || key == nil {
		return resp
	}

	doBit := hasDOBit(req)
	if !doBit {
		return resp
	}

	ksk := key
	zsk := zone.ZSKKey
	if zsk == nil {
		zsk = ksk
	}

	kskPub := BuildDNSKEYRecord(zone.Name, ksk, zone.DNSSEC.Algorithm, zone.SOA().TTLSec)
	if kskPub == nil {
		return resp
	}
	kskPub.Flags = 257

	kskWire, err := kskPub.RData()
	if err != nil {
		return resp
	}
	kskTag := ComputeKeyTag(kskWire, zone.DNSSEC.Algorithm, zone.Name)

	var zskPub *DNSKEYRecord
	var zskTag uint16
	useSeparateZSK := ksk != zsk
	if useSeparateZSK {
		zskPub = BuildDNSKEYRecord(zone.Name, zsk, zone.DNSSEC.Algorithm, zone.SOA().TTLSec)
		if zskPub == nil {
			zskPub = kskPub
			zskTag = kskTag
		} else {
			zskPub.Flags = 256
			zskWire, zerr := zskPub.RData()
			if zerr != nil {
				zskPub = kskPub
				zskTag = kskTag
			} else {
				zskTag = ComputeKeyTag(zskWire, zone.DNSSEC.Algorithm, zone.Name)
			}
		}
	} else {
		zskPub = kskPub
		zskTag = kskTag
	}

	var extraZSKs []*DNSKEYRecord
	if zone.Rollover != nil {
		phase := zone.Rollover.Phase()
		if phase == RolloverActive {
			if oldRec := zone.Rollover.OldDNSKEYRecord(); oldRec != nil {
				extraZSKs = append(extraZSKs, oldRec)
			}
		}
		if phase == RolloverPublishing {
			if newKey := zone.Rollover.NewZSK(); newKey != nil {
				nr := BuildDNSKEYRecord(zone.Name, newKey, zone.DNSSEC.Algorithm, zone.SOA().TTLSec)
				if nr != nil {
					nr.Flags = 256
					extraZSKs = append(extraZSKs, nr)
				}
			}
		}
	}

	type sigKey struct{ name, rtype string }
	answerGroups := make(map[sigKey][]Record)
	for _, ans := range resp.Answers {
		for _, r := range zone.byName[ans.Name] {
			if r.DNSType() == ans.Type {
				key := sigKey{ans.Name, fmt.Sprintf("%d", ans.Type)}
				answerGroups[key] = append(answerGroups[key], r)
				break
			}
		}
	}

	var addlRRSIGs []dns.ResourceRecord
	for _, group := range answerGroups {
		rrsig, err := SignRRset(group, zone.Name, zsk, zone.DNSSEC.Algorithm, zskTag)
		if err != nil {
			continue
		}
		rdata, err := rrsig.RData()
		if err != nil {
			continue
		}
		addlRRSIGs = append(addlRRSIGs, dns.ResourceRecord{
			Name:     rrsig.DNSName(),
			Type:     dns.TypeRRSIG,
			Class:    1,
			TTL:      rrsig.TTL(),
			RDLength: uint16(len(rdata)),
			RData:    rdata,
		})
	}

	soaRecords := findSOARecords(zone)
	if len(soaRecords) > 0 {
		rrsig, err := SignRRset(soaRecords, zone.Name, zsk, zone.DNSSEC.Algorithm, zskTag)
		if err == nil {
			rdata, _ := rrsig.RData()
			addlRRSIGs = append(addlRRSIGs, dns.ResourceRecord{
				Name:     rrsig.DNSName(),
				Type:     dns.TypeRRSIG,
				Class:    1,
				TTL:      rrsig.TTL(),
				RDLength: uint16(len(rdata)),
				RData:    rdata,
			})
		}
	}

	respRrsigs := addlRRSIGs

	if resp.Header.Flags&0x000F == 3 {
		if zone.DNSSEC.NSEC3 {
			iterations := uint16(0)
			var salt []byte
			nsec3Chain := BuildNSEC3Chain(zone, iterations, salt, false)
			for _, nsec3 := range nsec3Chain {
				rdata, _ := nsec3.RData()
				resp.Authorities = append(resp.Authorities, dns.ResourceRecord{
					Name:     nsec3.DNSName(),
					Type:     dns.TypeNSEC3,
					Class:    1,
					TTL:      nsec3.TTL(),
					RDLength: uint16(len(rdata)),
					RData:    rdata,
				})
			}
			param := BuildNSEC3PARAMRecord(zone, iterations, salt)
			prdata, _ := param.RData()
			resp.Additionals = append(resp.Additionals, dns.ResourceRecord{
				Name:     param.DNSName(),
				Type:     dns.TypeNSEC3PARAM,
				Class:    1,
				TTL:      param.TTL(),
				RDLength: uint16(len(prdata)),
				RData:    prdata,
			})
		} else {
			nsecChain := BuildNSECChain(zone)
			for _, nsec := range nsecChain {
				rdata, _ := nsec.RData()
				resp.Authorities = append(resp.Authorities, dns.ResourceRecord{
					Name:     nsec.DNSName(),
					Type:     dns.TypeNSEC,
					Class:    1,
					TTL:      nsec.TTL(),
					RDLength: uint16(len(rdata)),
					RData:    rdata,
				})
			}
		}
	}

	resp.Answers = append(resp.Answers, respRrsigs...)

	if useSeparateZSK {
		zskRData, _ := zskPub.RData()
		resp.Additionals = append(resp.Additionals, dns.ResourceRecord{
			Name:     zone.Name,
			Type:     dns.TypeDNSKEY,
			Class:    1,
			TTL:      zskPub.TTL(),
			RDLength: uint16(len(zskRData)),
			RData:    zskRData,
		})
	}
	for _, extra := range extraZSKs {
		erData, _ := extra.RData()
		resp.Additionals = append(resp.Additionals, dns.ResourceRecord{
			Name:     zone.Name,
			Type:     dns.TypeDNSKEY,
			Class:    1,
			TTL:      extra.TTL(),
			RDLength: uint16(len(erData)),
			RData:    erData,
		})
	}

	kskRData, _ := kskPub.RData()
	resp.Additionals = append([]dns.ResourceRecord{{
		Name:     zone.Name,
		Type:     dns.TypeDNSKEY,
		Class:    1,
		TTL:      kskPub.TTL(),
		RDLength: uint16(len(kskRData)),
		RData:    kskRData,
	}}, resp.Additionals...)

	kdns := []Record{kskPub}
	if useSeparateZSK {
		kdns = append(kdns, zskPub)
	}
	for _, extra := range extraZSKs {
		kdns = append(kdns, extra)
	}
	dnskeySig, err := SignRRset(kdns, zone.Name, ksk, zone.DNSSEC.Algorithm, kskTag)
	if err == nil {
		sigRData, _ := dnskeySig.RData()
		resp.Additionals = append(resp.Additionals, dns.ResourceRecord{
			Name:     zone.Name,
			Type:     dns.TypeRRSIG,
			Class:    1,
			TTL:      dnskeySig.TTL(),
			RDLength: uint16(len(sigRData)),
			RData:    sigRData,
		})
	}

	resp.Header.ARCount = uint16(len(resp.Additionals))
	resp.Header.ANCount = uint16(len(resp.Answers))
	resp.Header.NSCount = uint16(len(resp.Authorities))

	return resp
}

func hasDOBit(req *dns.Message) bool {
	for _, rr := range req.Additionals {
		if rr.Type == dns.TypeOPT {
			return rr.TTL&0x8000 != 0
		}
	}
	return false
}

func findSOARecords(zone *Zone) []Record {
	for _, r := range zone.byName[zone.Name] {
		if r.DNSType() == dns.TypeSOA {
			return []Record{r}
		}
	}
	return nil
}
