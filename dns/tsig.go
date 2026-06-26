// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package dns

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"time"
)

const (
	AlgHMACMD5    = "hmac-md5.sig-alg.reg.int"
	AlgHMACSHA1   = "hmac-sha1"
	AlgHMACSHA256 = "hmac-sha256"
	AlgHMACSHA512 = "hmac-sha512"
)

const (
	TSIGErrNoError  = 0
	TSIGErrBadSig   = 16
	TSIGErrBadKey   = 17
	TSIGErrBadTime  = 18
	TSIGErrBadMode  = 19
	TSIGErrBadName  = 20
	TSIGErrBadAlg   = 21
	TSIGErrBadTrunc = 22
)

type TSIG struct {
	Algorithm  string
	TimeSigned uint64
	Fudge      uint16
	MAC        []byte
	OriginalID uint16
	Error      uint16
	OtherLen   uint16
	OtherData  []byte
}

func ParseTSIG(rr *ResourceRecord) (*TSIG, error) {
	if rr.Type != TypeTSIG {
		return nil, errors.New("dns: not a TSIG record")
	}
	data := rr.RData
	if len(data) < 10 {
		return nil, errors.New("dns: TSIG too short")
	}

	tsig := &TSIG{}

	off := 0
	algName, newOff, err := readName(data, off, map[int]bool{})
	if err != nil {
		return nil, err
	}
	tsig.Algorithm = algName
	off = newOff

	if off+6 > len(data) {
		return nil, errors.New("dns: TSIG truncated after algorithm")
	}
	tsig.TimeSigned = (uint64(data[off]) << 40) |
		(uint64(data[off+1]) << 32) |
		(uint64(data[off+2]) << 24) |
		(uint64(data[off+3]) << 16) |
		(uint64(data[off+4]) << 8) |
		uint64(data[off+5])
	off += 6

	if off+2 > len(data) {
		return nil, errors.New("dns: TSIG truncated after time signed")
	}
	tsig.Fudge = binary.BigEndian.Uint16(data[off : off+2])
	off += 2

	if off+2 > len(data) {
		return nil, errors.New("dns: TSIG truncated after fudge")
	}
	macLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2

	if macLen > 0 {
		if off+macLen > len(data) {
			return nil, errors.New("dns: TSIG MAC truncated")
		}
		tsig.MAC = make([]byte, macLen)
		copy(tsig.MAC, data[off:off+macLen])
		off += macLen
	}

	if off+2 > len(data) {
		return nil, errors.New("dns: TSIG truncated after MAC")
	}
	tsig.OriginalID = binary.BigEndian.Uint16(data[off : off+2])
	off += 2

	if off+2 > len(data) {
		return nil, errors.New("dns: TSIG truncated after original ID")
	}
	tsig.Error = binary.BigEndian.Uint16(data[off : off+2])
	off += 2

	if off+2 > len(data) {
		return nil, errors.New("dns: TSIG truncated after error")
	}
	otherLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2

	if otherLen > 0 {
		if off+otherLen > len(data) {
			return nil, errors.New("dns: TSIG other data truncated")
		}
		tsig.OtherData = make([]byte, otherLen)
		copy(tsig.OtherData, data[off:off+otherLen])
	}
	tsig.OtherLen = uint16(otherLen)

	return tsig, nil
}

func PackTSIG(tsig *TSIG) ([]byte, error) {
	var buf []byte

	buf = appendName(buf, tsig.Algorithm)

	var timeBuf [6]byte
	timeBuf[0] = byte(tsig.TimeSigned >> 40)
	timeBuf[1] = byte(tsig.TimeSigned >> 32)
	timeBuf[2] = byte(tsig.TimeSigned >> 24)
	timeBuf[3] = byte(tsig.TimeSigned >> 16)
	timeBuf[4] = byte(tsig.TimeSigned >> 8)
	timeBuf[5] = byte(tsig.TimeSigned)
	buf = append(buf, timeBuf[:]...)

	buf = binary.BigEndian.AppendUint16(buf, tsig.Fudge)

	macLen := len(tsig.MAC)
	buf = binary.BigEndian.AppendUint16(buf, uint16(macLen))
	if macLen > 0 {
		buf = append(buf, tsig.MAC...)
	}

	buf = binary.BigEndian.AppendUint16(buf, tsig.OriginalID)
	buf = binary.BigEndian.AppendUint16(buf, tsig.Error)

	otherLen := len(tsig.OtherData)
	buf = binary.BigEndian.AppendUint16(buf, uint16(otherLen))
	if otherLen > 0 {
		buf = append(buf, tsig.OtherData...)
	}

	return buf, nil
}

func TSIGHashForAlgorithm(alg string) (func() hash.Hash, error) {
	alg = trimSuffix(alg, ".")
	switch alg {
	case "hmac-md5.sig-alg.reg.int", "hmac-md5":
		return md5.New, nil
	case "hmac-sha1":
		return sha1.New, nil
	case "hmac-sha256":
		return sha256.New, nil
	case "hmac-sha512":
		return sha512.New, nil
	default:
		return nil, errors.New("dns: unknown TSIG algorithm: " + alg)
	}
}

func TSIGKeyLength(alg string) int {
	alg = trimSuffix(alg, ".")
	switch alg {
	case "hmac-md5.sig-alg.reg.int", "hmac-md5":
		return 16
	case "hmac-sha1":
		return 20
	case "hmac-sha256":
		return 32
	case "hmac-sha512":
		return 64
	default:
		return 0
	}
}

func ExtractTSIG(msg *Message) *TSIG {
	for _, rr := range msg.Additionals {
		if rr.Type == TypeTSIG {
			tsig, err := ParseTSIG(&rr)
			if err != nil {
				return nil
			}
			return tsig
		}
	}
	return nil
}

func RemoveTSIG(msg *Message) {
	for i := len(msg.Additionals) - 1; i >= 0; i-- {
		if msg.Additionals[i].Type == TypeTSIG {
			msg.Additionals = append(msg.Additionals[:i], msg.Additionals[i+1:]...)
			msg.Header.ARCount--
			return
		}
	}
}

func ComputeTSIGMAC(msg *Message, tsig *TSIG, key []byte) ([]byte, error) {
	hf, err := TSIGHashForAlgorithm(tsig.Algorithm)
	if err != nil {
		return nil, err
	}
	if len(key) == 0 {
		return nil, errors.New("dns: TSIG key is empty")
	}

	macH := hmac.New(hf, key)

	// Build a message copy with the TSIG record (MAC field zeroed) in the additional section.
	// Per RFC 2845 §3.4.3, the MAC is computed over:
	//   1. The DNS message including the TSIG record (MAC=0)
	//   2. The TSIG variables (algorithm, time, fudge, error, other)

	msgCopy := &Message{
		Header: Header{
			ID:      msg.Header.ID,
			Flags:   msg.Header.Flags,
			QDCount: msg.Header.QDCount,
			ANCount: msg.Header.ANCount,
			NSCount: msg.Header.NSCount,
			ARCount: msg.Header.ARCount,
		},
		Questions:   copyQuestions(msg.Questions),
		Answers:     copyRRs(msg.Answers),
		Authorities: copyRRs(msg.Authorities),
		Additionals: copyRRs(msg.Additionals),
	}

	// Remove any existing TSIG from the copy
	for i := len(msgCopy.Additionals) - 1; i >= 0; i-- {
		if msgCopy.Additionals[i].Type == TypeTSIG {
			msgCopy.Additionals = append(msgCopy.Additionals[:i], msgCopy.Additionals[i+1:]...)
			msgCopy.Header.ARCount--
		}
	}

	// Create the TSIG record with zeroed MAC for MAC computation
	tsigForMAC := &TSIG{
		Algorithm:  tsig.Algorithm,
		TimeSigned: tsig.TimeSigned,
		Fudge:      tsig.Fudge,
		MAC:        nil,
		OriginalID: tsig.OriginalID,
		Error:      tsig.Error,
		OtherLen:   tsig.OtherLen,
		OtherData:  tsig.OtherData,
	}

	rdata, err := PackTSIG(tsigForMAC)
	if err != nil {
		return nil, err
	}

	msgCopy.Additionals = append(msgCopy.Additionals, ResourceRecord{
		Name:     "",
		Type:     TypeTSIG,
		Class:    0,
		TTL:      0,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	})
	msgCopy.Header.ARCount++

	packed := msgCopy.Pack()
	macH.Write(packed)

	writeTSIGVariables(macH, tsig)

	return macH.Sum(nil), nil
}

func writeTSIGVariables(w hash.Hash, tsig *TSIG) {
	alg := trimSuffix(tsig.Algorithm, ".")
	labels := splitLabels(alg)
	for _, label := range labels {
		w.Write([]byte{byte(len(label))})
		w.Write([]byte(lowerName(label)))
	}
	w.Write([]byte{0})

	var timeBuf [6]byte
	timeBuf[0] = byte(tsig.TimeSigned >> 40)
	timeBuf[1] = byte(tsig.TimeSigned >> 32)
	timeBuf[2] = byte(tsig.TimeSigned >> 24)
	timeBuf[3] = byte(tsig.TimeSigned >> 16)
	timeBuf[4] = byte(tsig.TimeSigned >> 8)
	timeBuf[5] = byte(tsig.TimeSigned)
	w.Write(timeBuf[:])

	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], tsig.Fudge)
	w.Write(buf[:])

	binary.BigEndian.PutUint16(buf[:], tsig.Error)
	w.Write(buf[:])

	binary.BigEndian.PutUint16(buf[:], tsig.OtherLen)
	w.Write(buf[:])

	if len(tsig.OtherData) > 0 {
		w.Write(tsig.OtherData)
	}
}

func lowerName(name string) string {
	b := make([]byte, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func copyRRs(src []ResourceRecord) []ResourceRecord {
	dst := make([]ResourceRecord, len(src))
	copy(dst, src)
	return dst
}

func copyQuestions(src []Question) []Question {
	dst := make([]Question, len(src))
	copy(dst, src)
	return dst
}

func SignMessage(msg *Message, tsig *TSIG, key []byte) error {
	if tsig.TimeSigned == 0 {
		tsig.TimeSigned = uint64(time.Now().Unix())
	}
	if tsig.Fudge == 0 {
		tsig.Fudge = 300
	}

	mac, err := ComputeTSIGMAC(msg, tsig, key)
	if err != nil {
		return err
	}
	tsig.MAC = mac

	rdata, err := PackTSIG(tsig)
	if err != nil {
		return err
	}

	msg.Additionals = append(msg.Additionals, ResourceRecord{
		Name:     "",
		Type:     TypeTSIG,
		Class:    0,
		TTL:      0,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	})
	msg.Header.ARCount++

	return nil
}

func VerifyTSIG(msg *Message, tsig *TSIG, key []byte) error {
	if len(tsig.MAC) == 0 {
		return errors.New("dns: TSIG MAC is empty")
	}

	savedMAC := make([]byte, len(tsig.MAC))
	copy(savedMAC, tsig.MAC)

	computedMAC, err := ComputeTSIGMAC(msg, tsig, key)
	if err != nil {
		tsig.MAC = savedMAC
		return err
	}
	tsig.MAC = savedMAC

	if !hmac.Equal(computedMAC, savedMAC) {
		return errors.New("dns: TSIG MAC mismatch")
	}

	now := uint64(time.Now().Unix())
	if now < tsig.TimeSigned-uint64(tsig.Fudge) || now > tsig.TimeSigned+uint64(tsig.Fudge) {
		return errors.New("dns: TSIG time outside fudge window")
	}

	if tsig.Error != TSIGErrNoError {
		return errors.New("dns: TSIG error code indicates problem")
	}

	return nil
}
