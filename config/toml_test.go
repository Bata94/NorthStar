// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTOMLDefaults(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := filepath.Join(dir, "northstar.toml")
	if err := WriteDefaultConfigTOML(path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	fc, err := loadFileTOMLBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	if fc.Mode == nil || *fc.Mode != "prod" {
		t.Errorf("Mode = %v, want prod", fc.Mode)
	}
	if fc.DNSPort == nil || *fc.DNSPort != 53 {
		t.Errorf("DNSPort = %v, want 53", fc.DNSPort)
	}
	if fc.UpstreamAddr == nil || *fc.UpstreamAddr != "8.8.8.8:53" {
		t.Errorf("UpstreamAddr = %v, want 8.8.8.8:53", fc.UpstreamAddr)
	}
	if len(fc.Upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(fc.Upstreams))
	}
	if *fc.Upstreams[0].Name != "default" {
		t.Errorf("upstream name = %v, want default", *fc.Upstreams[0].Name)
	}
}

func TestTOMLFileOverride(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := filepath.Join(dir, "northstar.toml")

	tomlData := `
mode = "dev"
dns_port = 5353
`
	if err := os.WriteFile(path, []byte(tomlData), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	fcTOML, err := loadFileTOML(path)
	if err != nil {
		t.Fatal(err)
	}

	if *fcTOML.Mode != "dev" {
		t.Errorf("Mode = %v, want dev", *fcTOML.Mode)
	}
	if *fcTOML.DNSPort != 5353 {
		t.Errorf("DNSPort = %v, want 5353", *fcTOML.DNSPort)
	}

	fc := tomlConfigToFileConfig(fcTOML)

	if *fc.Mode != "dev" {
		t.Errorf("Mode = %v, want dev", *fc.Mode)
	}
	if *fc.DNSPort != 5353 {
		t.Errorf("DNSPort = %v, want 5353", *fc.DNSPort)
	}
}

func TestTOMLRoundTrip(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := filepath.Join(dir, "northstar.toml")

	if err := WriteDefaultConfigTOML(path); err != nil {
		t.Fatal(err)
	}

	t.Setenv("NORTHSTAR_CONFIG", path)

	cfg := Load()

	if cfg.Mode != "prod" {
		t.Errorf("Mode = %s, want prod", cfg.Mode)
	}
	if cfg.DNSPort != 53 {
		t.Errorf("DNSPort = %d, want 53", cfg.DNSPort)
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].Name != "default" {
		t.Errorf("Upstreams = %v, want [default]", cfg.Upstreams)
	}
}

func TestTOMLEnvOverride(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := filepath.Join(dir, "northstar.toml")

	tomlData := `
mode = "prod"
dns_port = 5353
`
	if err := os.WriteFile(path, []byte(tomlData), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)
	t.Setenv("NORTHSTAR_MODE", "dev")

	cfg := Load()

	if cfg.Mode != "dev" {
		t.Errorf("Mode = %s, want dev (env should win)", cfg.Mode)
	}
	if cfg.DNSPort != 5353 {
		t.Errorf("DNSPort = %d, want 5353", cfg.DNSPort)
	}
}

func TestTOMLWithZones(t *testing.T) {
	clearEnv()
	dir := t.TempDir()
	path := filepath.Join(dir, "northstar.toml")

	tomlData := `
[[zones]]
name = "example.com"

[[zones.records]]
name = "@"
type = "A"
ip = "192.0.2.1"
ttl = 3600

[[zones.records]]
name = "www"
type = "A"
ip = "192.0.2.2"
ttl = 3600

[zones.dnssec]
enabled = true
algorithm = "ecdsa-p256"
`
	if err := os.WriteFile(path, []byte(tomlData), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NORTHSTAR_CONFIG", path)

	fcTOML, err := loadFileTOML(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(fcTOML.Zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(fcTOML.Zones))
	}
	if *fcTOML.Zones[0].Name != "example.com" {
		t.Errorf("zone name = %v, want example.com", *fcTOML.Zones[0].Name)
	}

	fc := tomlConfigToFileConfig(fcTOML)
	if len(fc.Zones) != 1 {
		t.Fatalf("expected 1 zone in converted config, got %d", len(fc.Zones))
	}
	if *fc.Zones[0].Name != "example.com" {
		t.Errorf("converted zone name = %v, want example.com", *fc.Zones[0].Name)
	}
}

func TestTOMLYAMLMutualExclusive(t *testing.T) {
	clearEnv()
	dir := t.TempDir()

	yamlPath := filepath.Join(dir, "northstar.yaml")
	yamlData := "mode: prod\ndns_port: 53\n"
	if err := os.WriteFile(yamlPath, []byte(yamlData), 0644); err != nil {
		t.Fatal(err)
	}

	tomlPath := filepath.Join(dir, "northstar.toml")
	tomlData := "mode = \"dev\"\ndns_port = 5353\n"
	if err := os.WriteFile(tomlPath, []byte(tomlData), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("NORTHSTAR_CONFIG", yamlPath)
	cfg := Load()

	if cfg.Mode != "prod" {
		t.Errorf("Mode = %s, want prod (YAML should take priority)", cfg.Mode)
	}
}

func TestTOMLNoFileFallback(t *testing.T) {
	clearEnv()
	t.Setenv("NORTHSTAR_MODE", "dev")

	cfg := Load()

	if cfg.Mode != "dev" {
		t.Errorf("Mode = %s, want dev (env only)", cfg.Mode)
	}
	if cfg.DNSPort != 53 {
		t.Errorf("DNSPort = %d, want 53 (default)", cfg.DNSPort)
	}
}
