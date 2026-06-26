// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package config

import (
	"os"
	"testing"
)

func TestValidateDefaults(t *testing.T) {
	clearEnv()
	errs := Validate()
	if len(errs) == 0 {
		t.Fatal("expected error for missing config file")
	}
}

func TestValidateValidConfig(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"

	if err := WriteDefaultConfig(path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	for _, e := range errs {
		t.Errorf("unexpected error: %v", e)
	}
}

func TestValidateBothIPv4AndIPv6Disabled(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `ipv4_disable: true
ipv6_disable: true
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "ipv4_disable/ipv6_disable: both IPv4 and IPv6 cannot be disabled" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected both IPv4/IPv6 disabled error, got %v", errs)
	}
}

func TestValidateInvalidPort(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `dns_port: 99999
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "dns_port: must be between 1 and 65535, got 99999" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected port error, got %v", errs)
	}
}

func TestValidateUpstreamMissingPort(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `upstreams:
  - name: test
    address: 1.2.3.4
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "upstreams[test]: missing port in address \"1.2.3.4\"; use host:port format" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected missing port error, got %v", errs)
	}
}

func TestValidateDuplicateUpstreamName(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `upstreams:
  - name: dup
    address: 8.8.8.8:53
  - name: dup
    address: 1.1.1.1:53
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "upstreams[1]: duplicate upstream name \"dup\"" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected duplicate name error, got %v", errs)
	}
}

func TestValidateCacheMutualExclusive(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `cache_addr: "127.0.0.1:6379"
cache_file: "/tmp/cache.db"
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "cache: cache_addr and cache_file are mutually exclusive" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected cache mutual exclusive error, got %v", errs)
	}
}

func TestValidateTTLMinMax(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `ttl_min: 300
ttl_max: 60
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "ttl_min/ttl_max: ttl_min (300) cannot exceed ttl_max (60)" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TTL order error, got %v", errs)
	}
}

func TestValidateTLSMissingKey(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `tls:
  cert_file: /tmp/cert.pem
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "tls.cert_file: cert_file is set but key_file is missing" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TLS missing key error, got %v", errs)
	}
}

func TestValidateInvalidACLSubnet(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `acls:
  - name: test
    action: allow
    subnet: not-a-cidr
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "acls[test]: invalid subnet \"not-a-cidr\": invalid CIDR address: not-a-cidr" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid subnet error, got %v", errs)
	}
}

func TestValidateInvalidLogLevel(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `log_level: trace
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "log_level: must be one of: debug, info, warn, error; got \"trace\"" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid log level error, got %v", errs)
	}
}

func TestValidateInvalidTracingSampleRate(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `tracing:
  sample_rate: 2.5
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "tracing.sample_rate: must be between 0.0 and 1.0, got 2.500000" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sample rate error, got %v", errs)
	}
}

func TestValidateInvalidBlockAction(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `hooks:
  blocking:
    enabled: true
    block_action: invalid
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "hooks.blocking.block_action: must be one of: nxdomain, sinkhole, refused, drop; got \"invalid\"" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid block action error, got %v", errs)
	}
}

func TestValidatePortConflict(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `dns_port: 853
dot_port: 853
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "dns_port: port 853 conflicts with dot_port" || e.Error() == "dot_port: port 853 conflicts with dns_port" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected port conflict error, got %v", errs)
	}
}

func TestValidateInvalidDoHURL(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `upstreams:
  - name: test
    address: 8.8.8.8:53
    doh_url: "http://example.com/dns-query"
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "upstreams[test]: DoH URL \"http://example.com/dns-query\" must start with https://" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DoH URL error, got %v", errs)
	}
}

func TestValidateDHCPLeaseFileWithoutEnabled(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `dhcp:
  lease_file: /tmp/dhcp.leases
  enabled: false
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "dhcp.lease_file: lease_file is set but dhcp.enabled is false" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DHCP lease file error, got %v", errs)
	}
}

func TestValidateInvalidForwardingZoneMode(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `forwarding_zones:
  - domain: example.com
    upstreams: ["8.8.8.8:53"]
    mode: invalid
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "forwarding_zones[example.com]: mode must be 'forward-only' or 'forward-first', got \"invalid\"" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected forwarding zone mode error, got %v", errs)
	}
}

func TestValidateEDNSPaddingNotPowerOf2(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `edns:
  padding_block_size: 100
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	found := false
	for _, e := range errs {
		if e.Error() == "edns.padding_block_size: must be a power of 2 (e.g., 0, 128, 256) or 0 to disable" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected EDNS padding error, got %v", errs)
	}
}

func TestValidateAndExitNoErrors(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	if err := WriteDefaultConfig(path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	if code := ValidateAndExit(); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestValidateAndExitWithErrors(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.yaml"
	yaml := `ipv4_disable: true
ipv6_disable: true
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	if code := ValidateAndExit(); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestValidateTOMLConfig(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := dir + "/northstar.toml"

	if err := WriteDefaultConfigTOML(path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	errs := Validate()
	for _, e := range errs {
		t.Errorf("unexpected error: %v", e)
	}
}
