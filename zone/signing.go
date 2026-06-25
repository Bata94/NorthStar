package zone

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
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

	pubKey := BuildDNSKEYRecord(zone.Name, key, zone.DNSSEC.Algorithm, zone.SOA().TTLSec)
	if pubKey == nil {
		return resp
	}

	pubKeyWire, err := pubKey.RData()
	if err != nil {
		return resp
	}
	dnskeyTag := ComputeKeyTag(pubKeyWire, zone.DNSSEC.Algorithm, zone.Name)

	// Group answer records by name+type for signing
	type sigKey struct{ name, rtype string }
	answerGroups := make(map[sigKey][]Record)
	for _, ans := range resp.Answers {
		// Find matching Record in zone
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
		rrsig, err := SignRRset(group, zone.Name, key, zone.DNSSEC.Algorithm, dnskeyTag)
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

	// Sign SOA if in authority
	soaRecords := findSOARecords(zone)
	if len(soaRecords) > 0 {
		rrsig, err := SignRRset(soaRecords, zone.Name, key, zone.DNSSEC.Algorithm, dnskeyTag)
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

	// Add RRSIGs for negative responses (authority SOA)
	respRrsigs := addlRRSIGs

	// Build NSEC chain and include if NXDOMAIN
	if resp.Header.Flags&0x000F == 3 {
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

	resp.Answers = append(resp.Answers, respRrsigs...)

	pubRData, _ := pubKey.RData()
	resp.Additionals = append([]dns.ResourceRecord{{
		Name:     zone.Name,
		Type:     dns.TypeDNSKEY,
		Class:    1,
		TTL:      pubKey.TTL(),
		RDLength: uint16(len(pubRData)),
		RData:    pubRData,
	}}, resp.Additionals...)

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
