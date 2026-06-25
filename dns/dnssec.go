// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package dns

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
)

const (
	AlgRSAMD5    = 1
	AlgRSASHA1   = 5
	AlgRSASHA256 = 8
	AlgRSASHA512 = 10
	AlgECDSAP256 = 13
	AlgECDSAP384 = 14
	AlgED25519   = 15
	AlgED448     = 16

	DigestSHA1   = 1
	DigestSHA256 = 2
	DigestGOST   = 3
	DigestSHA384 = 4
)

type RRSIG struct {
	TypeCovered   uint16
	Algorithm     uint8
	Labels        uint8
	OriginalTTL   uint32
	SigExpiration uint32
	SigInception  uint32
	KeyTag        uint16
	SignerName    string
	Signature     []byte
}

type DNSKEY struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey []byte
}

type DS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

type NSEC struct {
	NextDomain  string
	TypeBitMaps []uint16
}

func ParseRRSIG(rr *ResourceRecord) (*RRSIG, error) {
	if rr.Type != TypeRRSIG {
		return nil, errors.New("dns: not an RRSIG record")
	}
	data := rr.RData
	if len(data) < 18 {
		return nil, errors.New("dns: RRSIG too short")
	}
	sig := &RRSIG{
		TypeCovered:   binary.BigEndian.Uint16(data[0:2]),
		Algorithm:     data[2],
		Labels:        data[3],
		OriginalTTL:   binary.BigEndian.Uint32(data[4:8]),
		SigExpiration: binary.BigEndian.Uint32(data[8:12]),
		SigInception:  binary.BigEndian.Uint32(data[12:16]),
		KeyTag:        binary.BigEndian.Uint16(data[16:18]),
	}
	off := 18
	name, newOff, err := readName(data, off, map[int]bool{})
	if err != nil {
		return nil, err
	}
	sig.SignerName = name
	off = newOff
	if off >= len(data) {
		return nil, errors.New("dns: RRSIG truncated after signer name")
	}
	sig.Signature = make([]byte, len(data)-off)
	copy(sig.Signature, data[off:])
	return sig, nil
}

func ParseDNSKEY(rr *ResourceRecord) (*DNSKEY, error) {
	if rr.Type != TypeDNSKEY {
		return nil, errors.New("dns: not a DNSKEY record")
	}
	data := rr.RData
	if len(data) < 4 {
		return nil, errors.New("dns: DNSKEY too short")
	}
	key := &DNSKEY{
		Flags:     binary.BigEndian.Uint16(data[0:2]),
		Protocol:  data[2],
		Algorithm: data[3],
		PublicKey: make([]byte, len(data)-4),
	}
	copy(key.PublicKey, data[4:])
	return key, nil
}

func ParseDS(rr *ResourceRecord) (*DS, error) {
	if rr.Type != TypeDS {
		return nil, errors.New("dns: not a DS record")
	}
	data := rr.RData
	if len(data) < 4 {
		return nil, errors.New("dns: DS too short")
	}
	ds := &DS{
		KeyTag:     binary.BigEndian.Uint16(data[0:2]),
		Algorithm:  data[2],
		DigestType: data[3],
	}
	if len(data) > 4 {
		ds.Digest = make([]byte, len(data)-4)
		copy(ds.Digest, data[4:])
	}
	return ds, nil
}

func (k *DNSKEY) IsKSK() bool {
	return k.Flags&0x0001 != 0
}

func (k *DNSKEY) IsZSK() bool {
	return k.Flags&0x0001 == 0
}

func DNSKEYKeyTag(owner string, pubKey []byte, algorithm uint8) uint16 {
	tagData := make([]byte, 0, len(owner)+len(pubKey)+4)
	for _, label := range splitLabels(owner) {
		tagData = append(tagData, byte(len(label)))
		tagData = append(tagData, []byte(label)...)
	}
	tagData = append(tagData, 0)
	tagData = binary.BigEndian.AppendUint16(tagData, 256)
	tagData = append(tagData, 0)
	tagData = append(tagData, algorithm)
	tagData = append(tagData, pubKey...)

	var ac uint32
	for i := 0; i < len(tagData); i++ {
		if i&1 == 0 {
			ac += uint32(tagData[i]) << 8
		} else {
			ac += uint32(tagData[i])
		}
	}
	ac += ac >> 16
	return uint16(ac & 0xFFFF)
}

func splitLabels(name string) []string {
	name = trimSuffix(name, ".")
	if name == "" {
		return nil
	}
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	return labels
}

func trimSuffix(s, suffix string) string {
	if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)]
	}
	return s
}

func DNSKEYPublicKey(dnskey *DNSKEY) (crypto.PublicKey, error) {
	switch dnskey.Algorithm {
	case AlgRSASHA1, AlgRSASHA256, AlgRSASHA512:
		data := dnskey.PublicKey
		if len(data) < 3 {
			return nil, errors.New("dns: RSA DNSKEY too short")
		}
		var expLen int
		if data[0] == 0 {
			if len(data) < 3 {
				return nil, errors.New("dns: RSA DNSKEY too short for exponent length")
			}
			expLen = int(data[1])<<8 | int(data[2])
			data = data[3:]
		} else {
			expLen = int(data[0])
			data = data[1:]
		}
		if expLen == 0 || len(data) < expLen {
			return nil, errors.New("dns: RSA DNSKEY exponent truncated")
		}
		expBytes := make([]byte, expLen)
		copy(expBytes, data[:expLen])
		data = data[expLen:]
		if len(data) == 0 {
			return nil, errors.New("dns: RSA DNSKEY modulus missing")
		}
		n := make([]byte, len(data))
		copy(n, data)
		e := 0
		for _, b := range expBytes {
			e = (e << 8) | int(b)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: e,
		}, nil
	case AlgECDSAP256:
		return parseECDSAKey(dnskey.PublicKey, 256)
	case AlgECDSAP384:
		return parseECDSAKey(dnskey.PublicKey, 384)
	case AlgED25519:
		if len(dnskey.PublicKey) != 32 {
			return nil, errors.New("dns: ed25519 key must be 32 bytes")
		}
		return ed25519.PublicKey(dnskey.PublicKey), nil
	default:
		return nil, errors.New("dns: unsupported DNSKEY algorithm")
	}
}

func parseECDSAKey(data []byte, bits int) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch bits {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	default:
		return nil, errors.New("dns: unsupported ECDSA key size")
	}
	x, y := elliptic.Unmarshal(curve, data) //nolint:staticcheck
	if x == nil {
		return nil, errors.New("dns: failed to unmarshal ECDSA key")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func VerifyRRSIG(rrset []ResourceRecord, rrsig *RRSIG, pubKey crypto.PublicKey) error {
	wire := rrsigWireForm(rrset, rrsig)
	hash := hashForAlgorithm(rrsig.Algorithm)

	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		digest := hashSum(hash, wire)
		return rsa.VerifyPKCS1v15(pub, hash, digest, rrsig.Signature)
	case *ecdsa.PublicKey:
		digest := hashSum(hash, wire)
		if len(rrsig.Signature)%2 != 0 {
			return errors.New("dns: invalid ECDSA signature length")
		}
		r := new(big.Int).SetBytes(rrsig.Signature[:len(rrsig.Signature)/2])
		s := new(big.Int).SetBytes(rrsig.Signature[len(rrsig.Signature)/2:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return errors.New("dns: ECDSA signature verification failed")
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, wire, rrsig.Signature) {
			return errors.New("dns: ed25519 signature verification failed")
		}
		return nil
	default:
		return errors.New("dns: unsupported public key type")
	}
}

func rrsigWireForm(rrset []ResourceRecord, rrsig *RRSIG) []byte {
	var buf []byte
	buf = appendName(buf, rrsig.SignerName)
	buf = binary.BigEndian.AppendUint16(buf, rrsig.TypeCovered)
	buf = binary.BigEndian.AppendUint16(buf, 1)
	buf = binary.BigEndian.AppendUint32(buf, rrsig.OriginalTTL)
	for _, rr := range rrset {
		buf = appendCanonicalRR(buf, &rr)
	}
	return buf
}

func appendCanonicalRR(buf []byte, rr *ResourceRecord) []byte {
	buf = appendName(buf, rr.Name)
	buf = binary.BigEndian.AppendUint16(buf, rr.Type)
	buf = binary.BigEndian.AppendUint16(buf, rr.Class)
	buf = binary.BigEndian.AppendUint32(buf, rr.TTL)
	rdlen := len(rr.RData)
	buf = binary.BigEndian.AppendUint16(buf, uint16(rdlen))
	buf = append(buf, rr.RData...)
	return buf
}

func appendName(buf []byte, name string) []byte {
	name = trimSuffix(name, ".")
	if name == "" {
		return append(buf, 0)
	}
	for _, label := range splitLabels(name) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0)
}

func hashForAlgorithm(alg uint8) crypto.Hash {
	switch alg {
	case AlgRSASHA1:
		return crypto.SHA1
	case AlgRSASHA256:
		return crypto.SHA256
	case AlgRSASHA512:
		return crypto.SHA512
	case AlgECDSAP256:
		return crypto.SHA256
	case AlgECDSAP384:
		return crypto.SHA384
	case AlgED25519:
		return crypto.Hash(0)
	default:
		return crypto.Hash(0)
	}
}

func hashSum(h crypto.Hash, data []byte) []byte {
	if h == crypto.Hash(0) {
		dst := make([]byte, len(data))
		copy(dst, data)
		return dst
	}
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil)
}

func VerifyDS(ds *DS, dnskey *DNSKEY, owner string) error {
	var digest []byte
	switch ds.DigestType {
	case DigestSHA1:
		h := sha1.New()
		h.Write([]byte(owner))
		if len(owner) > 0 && owner[len(owner)-1] != '.' {
			h.Write([]byte{0})
		}
		h.Write(dnskey.PublicKey)
		digest = h.Sum(nil)
	case DigestSHA256:
		h := sha256.New()
		h.Write([]byte(owner))
		if len(owner) > 0 && owner[len(owner)-1] != '.' {
			h.Write([]byte{0})
		}
		h.Write(dnskey.PublicKey)
		digest = h.Sum(nil)
	case DigestSHA384:
		h := sha512.New384()
		h.Write([]byte(owner))
		if len(owner) > 0 && owner[len(owner)-1] != '.' {
			h.Write([]byte{0})
		}
		h.Write(dnskey.PublicKey)
		digest = h.Sum(nil)
	default:
		return errors.New("dns: unsupported DS digest type")
	}
	if !bytes.Equal(digest, ds.Digest) {
		return errors.New("dns: DS digest mismatch")
	}
	return nil
}
