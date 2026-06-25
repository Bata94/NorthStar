// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package dns

import (
	"encoding/binary"
	"net"
)

const (
	EDNS0OptionECS = 8
	ECSFamilyIPv4  = 1
	ECSFamilyIPv6  = 2
)

func BuildECSOption(clientIP string, sourcePrefixLen int) []byte {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil
	}

	var family uint16
	var addrBytes []byte
	var addrLen int

	if ip4 := ip.To4(); ip4 != nil {
		family = ECSFamilyIPv4
		addrBytes = ip4
		addrLen = net.IPv4len
	} else if ip6 := ip.To16(); ip6 != nil {
		family = ECSFamilyIPv6
		addrBytes = ip6
		addrLen = net.IPv6len
	} else {
		return nil
	}

	if sourcePrefixLen > addrLen*8 {
		sourcePrefixLen = addrLen * 8
	}

	truncated := truncateIP(addrBytes, sourcePrefixLen)

	scopePrefix := uint8(0)
	optLen := 4 + len(truncated)

	opt := make([]byte, 4+optLen)
	binary.BigEndian.PutUint16(opt[0:2], EDNS0OptionECS)
	binary.BigEndian.PutUint16(opt[2:4], uint16(optLen))
	binary.BigEndian.PutUint16(opt[4:6], family)
	opt[6] = uint8(sourcePrefixLen)
	opt[7] = scopePrefix
	copy(opt[8:], truncated)

	return opt
}

func truncateIP(addr []byte, bits int) []byte {
	if bits >= len(addr)*8 {
		return addr
	}
	result := make([]byte, len(addr))
	copy(result, addr)

	fullBytes := bits / 8
	remainBits := bits % 8

	for i := 0; i < fullBytes; i++ {
		result[i] = addr[i]
	}
	if remainBits > 0 && fullBytes < len(addr) {
		mask := byte(0xFF << (8 - remainBits))
		result[fullBytes] = addr[fullBytes] & mask
		for i := fullBytes + 1; i < len(addr); i++ {
			result[i] = 0
		}
	} else if fullBytes < len(addr) {
		for i := fullBytes; i < len(addr); i++ {
			result[i] = 0
		}
	}

	return result
}
