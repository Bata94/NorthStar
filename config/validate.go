package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var validLogLevels = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
var validLogModes = map[string]bool{"dev": true, "prod": true}
var validBlockActions = map[string]bool{"nxdomain": true, "sinkhole": true, "refused": true, "drop": true}
var validACLActions = map[string]bool{"allow": true, "refuse": true, "drop": true, "route": true}
var validRRLActions = map[string]bool{"drop": true, "truncate": true}
var validTLSMinVersions = map[string]bool{"1.2": true, "1.3": true}
var validDHCPFormats = map[string]bool{"dnsmasq": true}
var validAnyQueryActions = map[string]bool{"minimal": true, "forward": true}
var validRateLimitActions = map[string]bool{"servfail": true, "drop": true}
var validTokenBucketModes = map[string]bool{"memory": true, "valkey": true}
var validDnssecValidationModes = map[string]bool{"required": true, "opportunistic": true}

type configError struct {
	field   string
	message string
}

func (e configError) Error() string {
	return fmt.Sprintf("%s: %s", e.field, e.message)
}

func Validate() []error {
	var errors []error

	cfgPath := "./northstar.yaml"
	if v, ok := os.LookupEnv("NORTHSTAR_CONFIG"); ok && v != "" {
		cfgPath = v
	}

	isTOML := strings.HasSuffix(cfgPath, ".toml")

	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if !isTOML {
			if _, err := os.Stat("./northstar.toml"); os.IsNotExist(err) {
				errors = append(errors, configError{"config", fmt.Sprintf("config file not found at %s or ./northstar.toml", cfgPath)})
			}
		} else {
			errors = append(errors, configError{"config", fmt.Sprintf("config file not found at %s", cfgPath)})
		}
		return errors
	}

	fc, err := loadFile(cfgPath)
	if err != nil {
		if isTOML {
			fcTOML, tErr := loadFileTOML(cfgPath)
			if tErr != nil {
				errors = append(errors, configError{"config", fmt.Sprintf("failed to parse %s: %v (yaml: %v)", cfgPath, tErr, err)})
				return errors
			}
			fc = tomlConfigToFileConfig(fcTOML)
		} else {
			errors = append(errors, configError{"config", fmt.Sprintf("failed to parse %s: %v", cfgPath, err)})
			return errors
		}
	}

	cfg := Config{
		ConfigPath: cfgPath,
	}
	applyDefaults(&cfg)
	applyFileConfig(&cfg, fc)
	applyFileZones(&cfg, fc)
	applyFileACLs(&cfg, fc)
	applyEnvOverrides(&cfg)
	migrateUpstreams(&cfg)

	errors = append(errors, validateGeneral(cfg)...)
	errors = append(errors, validateUpstreams(cfg)...)
	errors = append(errors, validateCache(cfg)...)
	errors = append(errors, validatePorts(cfg)...)
	errors = append(errors, validateTLS(cfg)...)
	errors = append(errors, validateZones(cfg)...)
	errors = append(errors, validateACLs(cfg)...)
	errors = append(errors, validateDHCP(cfg)...)
	errors = append(errors, validateLogging(cfg)...)
	errors = append(errors, validateTracing(cfg)...)
	errors = append(errors, validateHooks(cfg)...)

	return errors
}

func applyDefaults(cfg *Config) {
	if cfg.Mode == "" {
		cfg.Mode = "prod"
	}
	if cfg.DNSPort == 0 {
		cfg.DNSPort = 53
	}
	if cfg.UpstreamAddr == "" {
		cfg.UpstreamAddr = "8.8.8.8:53"
	}
	if cfg.UpstreamPoolSize == 0 {
		cfg.UpstreamPoolSize = 10
	}
	if cfg.UpstreamPoolIdle == 0 {
		cfg.UpstreamPoolIdle = 30
	}
	if cfg.StaleAge == 0 {
		cfg.StaleAge = 60
	}
	if cfg.LogDir == "" {
		cfg.LogDir = "."
	}
	if cfg.LogRetention == 0 {
		cfg.LogRetention = 7
	}
	if cfg.MetricsPort == 0 {
		cfg.MetricsPort = 9153
	}
	if cfg.APIPort == 0 {
		cfg.APIPort = 9163
	}
	if cfg.DoTPort == 0 {
		cfg.DoTPort = 853
	}
	if cfg.DoHPort == 0 {
		cfg.DoHPort = 443
	}
	if cfg.DoQPort == 0 {
		cfg.DoQPort = 853
	}
	if cfg.Dns64Prefix == "" {
		cfg.Dns64Prefix = "64:ff9b::/96"
	}
	if cfg.EcsPrefixV4 == 0 {
		cfg.EcsPrefixV4 = 24
	}
	if cfg.EcsPrefixV6 == 0 {
		cfg.EcsPrefixV6 = 56
	}
	if cfg.TLS.MinVersion == "" {
		cfg.TLS.MinVersion = "1.2"
	}
	if cfg.Tracing.Endpoint == "" {
		cfg.Tracing.Endpoint = "localhost:4317"
	}
	if cfg.Tracing.ServiceName == "" {
		cfg.Tracing.ServiceName = "northstar"
	}
	if cfg.Tracing.SampleRate == 0 {
		cfg.Tracing.SampleRate = 0.1
	}
	if cfg.DHCP.Format == "" {
		cfg.DHCP.Format = "dnsmasq"
	}
	if cfg.DHCP.Domain == "" {
		cfg.DHCP.Domain = "lan"
	}
	if cfg.DHCP.TTL == 0 {
		cfg.DHCP.TTL = 300
	}
	if cfg.DHCP.PollInterval == 0 {
		cfg.DHCP.PollInterval = 30
	}
	if cfg.Hooks.RateLimiting.Action == "" {
		cfg.Hooks.RateLimiting.Action = "servfail"
	}
	if cfg.Hooks.RateLimiting.Priority == 0 {
		cfg.Hooks.RateLimiting.Priority = 100
	}
	if cfg.Hooks.TokenBucket.Action == "" {
		cfg.Hooks.TokenBucket.Action = "servfail"
	}
	if cfg.Hooks.TokenBucket.Priority == 0 {
		cfg.Hooks.TokenBucket.Priority = 100
	}
	if cfg.Hooks.TokenBucket.Mode == "" {
		cfg.Hooks.TokenBucket.Mode = "memory"
	}
	if cfg.Hooks.ResponseRateLimiting.Priority == 0 {
		cfg.Hooks.ResponseRateLimiting.Priority = 800
	}
	if cfg.Hooks.ResponseRateLimiting.Action == "" {
		cfg.Hooks.ResponseRateLimiting.Action = "drop"
	}
	if cfg.Hooks.ResponseRateLimiting.Slip == 0 {
		cfg.Hooks.ResponseRateLimiting.Slip = 2
	}
	if cfg.Hooks.Blocking.Priority == 0 {
		cfg.Hooks.Blocking.Priority = 200
	}
	if cfg.Hooks.Blocking.BlockAction == "" {
		cfg.Hooks.Blocking.BlockAction = "nxdomain"
	}
	if cfg.Hooks.Blocking.SinkholeAddr == "" {
		cfg.Hooks.Blocking.SinkholeAddr = "127.0.0.1"
	}
	if cfg.Hooks.Blocking.StatsMaxDomains == 0 {
		cfg.Hooks.Blocking.StatsMaxDomains = 1000
	}
	if cfg.Hooks.Blocking.StatsMaxClients == 0 {
		cfg.Hooks.Blocking.StatsMaxClients = 1000
	}
	if cfg.Hooks.Blocking.StatsRetention == 0 {
		cfg.Hooks.Blocking.StatsRetention = 30
	}
	if cfg.Hooks.QMinimizer.Priority == 0 {
		cfg.Hooks.QMinimizer.Priority = 300
	}
	if cfg.Hooks.QMinimizer.KeepLabels == 0 {
		cfg.Hooks.QMinimizer.KeepLabels = 2
	}
	if cfg.Hooks.AnyQuery.Priority == 0 {
		cfg.Hooks.AnyQuery.Priority = 400
	}
	if cfg.Hooks.AnyQuery.Action == "" {
		cfg.Hooks.AnyQuery.Action = "minimal"
	}
	if cfg.Hooks.Dns64.Priority == 0 {
		cfg.Hooks.Dns64.Priority = 500
	}
	if cfg.Hooks.Dns64.Prefix == "" {
		cfg.Hooks.Dns64.Prefix = "64:ff9b::/96"
	}
	if cfg.Hooks.ECS.Priority == 0 {
		cfg.Hooks.ECS.Priority = 600
	}
	if cfg.Hooks.ECS.PrefixV4 == 0 {
		cfg.Hooks.ECS.PrefixV4 = 24
	}
	if cfg.Hooks.ECS.PrefixV6 == 0 {
		cfg.Hooks.ECS.PrefixV6 = 56
	}
	if cfg.Hooks.Dnssec.Priority == 0 {
		cfg.Hooks.Dnssec.Priority = 700
	}
	if cfg.Hooks.Dnssec.Validation == "" {
		cfg.Hooks.Dnssec.Validation = "opportunistic"
	}
	if cfg.Hooks.QueryLog.Priority == 0 {
		cfg.Hooks.QueryLog.Priority = 900
	}
	if cfg.Hooks.QueryLog.File == "" {
		cfg.Hooks.QueryLog.File = "./query.log"
	}
	if cfg.Hooks.QueryLog.RetentionDays == 0 {
		cfg.Hooks.QueryLog.RetentionDays = 7
	}
	if cfg.Hooks.SpecialDomain.Priority == 0 {
		cfg.Hooks.SpecialDomain.Priority = 60
	}
}

func validateGeneral(cfg Config) []error {
	var errs []error

	if cfg.Ipv4Disable && cfg.Ipv6Disable {
		errs = append(errs, configError{"ipv4_disable/ipv6_disable", "both IPv4 and IPv6 cannot be disabled"})
	}

	if cfg.TimeZone != "" {
		if _, err := time.LoadLocation(cfg.TimeZone); err != nil {
			errs = append(errs, configError{"timezone", fmt.Sprintf("invalid timezone %q: %v", cfg.TimeZone, err)})
		}
	}

	if cfg.NodeID != "" {
		if _, err := net.ParseMAC(cfg.NodeID); err == nil {
		} else if _, err := strconv.ParseInt(cfg.NodeID, 10, 64); err == nil {
		} else if len(cfg.NodeID) > 64 {
			errs = append(errs, configError{"node_id", "node_id is too long (max 64 characters)"})
		}
	}

	return errs
}

func validatePorts(cfg Config) []error {
	var errs []error

	portChecks := []struct {
		name string
		port int
	}{
		{"dns_port", cfg.DNSPort},
		{"dot_port", cfg.DoTPort},
		{"doh_port", cfg.DoHPort},
		{"doq_port", cfg.DoQPort},
		{"metrics_port", cfg.MetricsPort},
		{"api_port", cfg.APIPort},
	}

	for _, pc := range portChecks {
		if pc.port < 1 || pc.port > 65535 {
			errs = append(errs, configError{pc.name, fmt.Sprintf("must be between 1 and 65535, got %d", pc.port)})
		}
	}

	usedPorts := make(map[int]string)
	for _, pc := range portChecks {
		if pc.port >= 1 && pc.port <= 65535 {
			if existing, ok := usedPorts[pc.port]; ok {
				if !(pc.name == "dot_port" && existing == "doq_port") &&
					!(pc.name == "doq_port" && existing == "dot_port") {
					errs = append(errs, configError{pc.name, fmt.Sprintf("port %d conflicts with %s", pc.port, existing)})
				}
			}
			usedPorts[pc.port] = pc.name
		}
	}

	return errs
}

func validateUpstreams(cfg Config) []error {
	var errs []error

	names := make(map[string]bool)
	for i, u := range cfg.Upstreams {
		if u.Name == "" {
			errs = append(errs, configError{fmt.Sprintf("upstreams[%d]", i), "upstream name is required"})
			continue
		}
		if names[u.Name] {
			errs = append(errs, configError{fmt.Sprintf("upstreams[%d]", i), fmt.Sprintf("duplicate upstream name %q", u.Name)})
		}
		names[u.Name] = true

		if u.Address == "" {
			errs = append(errs, configError{fmt.Sprintf("upstreams[%s]", u.Name), "address is required"})
		} else if !strings.Contains(u.Address, ":") {
			errs = append(errs, configError{fmt.Sprintf("upstreams[%s]", u.Name), fmt.Sprintf("missing port in address %q; use host:port format", u.Address)})
		}

		if u.DoHURL != "" {
			if !strings.HasPrefix(u.DoHURL, "https://") {
				errs = append(errs, configError{fmt.Sprintf("upstreams[%s]", u.Name), fmt.Sprintf("DoH URL %q must start with https://", u.DoHURL)})
			} else if _, err := url.Parse(u.DoHURL); err != nil {
				errs = append(errs, configError{fmt.Sprintf("upstreams[%s]", u.Name), fmt.Sprintf("invalid DoH URL %q: %v", u.DoHURL, err)})
			}
		}

		if u.HTTPProxyAddress != "" {
			if !strings.HasPrefix(u.HTTPProxyAddress, "http://") && !strings.HasPrefix(u.HTTPProxyAddress, "https://") {
				errs = append(errs, configError{fmt.Sprintf("upstreams[%s]", u.Name), fmt.Sprintf("HTTP proxy address %q must start with http:// or https://", u.HTTPProxyAddress)})
			}
		}

		if u.Timeout < 0 {
			errs = append(errs, configError{fmt.Sprintf("upstreams[%s]", u.Name), "timeout cannot be negative"})
		}
		if u.AdaptiveTimeoutFactor < 0 {
			errs = append(errs, configError{fmt.Sprintf("upstreams[%s]", u.Name), "adaptive_timeout_factor cannot be negative"})
		}
	}

	for i, fz := range cfg.ForwardingZones {
		if fz.Domain == "" {
			errs = append(errs, configError{fmt.Sprintf("forwarding_zones[%d]", i), "domain is required"})
		}
		if len(fz.Upstreams) == 0 {
			errs = append(errs, configError{fmt.Sprintf("forwarding_zones[%s]", fz.Domain), "at least one upstream is required"})
		}
		if fz.Mode != "" && fz.Mode != "forward-only" && fz.Mode != "forward-first" {
			errs = append(errs, configError{fmt.Sprintf("forwarding_zones[%s]", fz.Domain), fmt.Sprintf("mode must be 'forward-only' or 'forward-first', got %q", fz.Mode)})
		}
	}

	hasForwardOnlyAll := false
	if len(cfg.Upstreams) == 0 && len(cfg.ForwardingZones) > 0 {
		allForwardOnly := true
		for _, fz := range cfg.ForwardingZones {
			if fz.Mode != "forward-only" {
				allForwardOnly = false
				break
			}
		}
		if allForwardOnly {
			hasForwardOnlyAll = true
		}
	}
	if len(cfg.Upstreams) == 0 && !hasForwardOnlyAll {
		errs = append(errs, configError{"upstreams", "no upstreams configured and no forwarding zones to handle all queries"})
	}

	return errs
}

func validateCache(cfg Config) []error {
	var errs []error

	if cfg.CacheAddr != "" && cfg.CacheFile != "" {
		errs = append(errs, configError{"cache", "cache_addr and cache_file are mutually exclusive"})
	}

	if cfg.NegativeTTL < 0 {
		errs = append(errs, configError{"negative_ttl", "cannot be negative"})
	}
	if cfg.NegativeTTLMin < 0 {
		errs = append(errs, configError{"negative_ttl_min", "cannot be negative"})
	}
	if cfg.TTLMin < 0 {
		errs = append(errs, configError{"ttl_min", "cannot be negative"})
	}
	if cfg.TTLMax < 0 {
		errs = append(errs, configError{"ttl_max", "cannot be negative"})
	}
	if cfg.TTLMin > 0 && cfg.TTLMax > 0 && cfg.TTLMin > cfg.TTLMax {
		errs = append(errs, configError{"ttl_min/ttl_max", fmt.Sprintf("ttl_min (%d) cannot exceed ttl_max (%d)", cfg.TTLMin, cfg.TTLMax)})
	}

	return errs
}

func validateTLS(cfg Config) []error {
	var errs []error

	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile == "" {
		errs = append(errs, configError{"tls.cert_file", "cert_file is set but key_file is missing"})
	}
	if cfg.TLS.KeyFile != "" && cfg.TLS.CertFile == "" {
		errs = append(errs, configError{"tls.key_file", "key_file is set but cert_file is missing"})
	}
	if cfg.TLS.CertFile != "" {
		if _, err := os.Stat(cfg.TLS.CertFile); os.IsNotExist(err) {
			errs = append(errs, configError{"tls.cert_file", fmt.Sprintf("file not found: %s", cfg.TLS.CertFile)})
		}
	}
	if cfg.TLS.KeyFile != "" {
		if _, err := os.Stat(cfg.TLS.KeyFile); os.IsNotExist(err) {
			errs = append(errs, configError{"tls.key_file", fmt.Sprintf("file not found: %s", cfg.TLS.KeyFile)})
		}
	}
	if cfg.TLS.MinVersion != "" && !validTLSMinVersions[cfg.TLS.MinVersion] {
		errs = append(errs, configError{"tls.min_version", fmt.Sprintf("must be one of: 1.2, 1.3; got %q", cfg.TLS.MinVersion)})
	}
	if (cfg.DoTEnabled || cfg.DoHEnabled || cfg.DoQEnabled) && !cfg.TLS.AutoSelfSigned && cfg.TLS.CertFile == "" {
		errs = append(errs, configError{"tls", "TLS-enabled listeners require auto_self_signed or cert_file"})
	}

	return errs
}

var validDomainRE = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.?$`)

func validateZones(cfg Config) []error {
	var errs []error

	zoneNames := make(map[string]int)
	for i, z := range cfg.Zones {
		if z.Name == "" {
			errs = append(errs, configError{fmt.Sprintf("zones[%d]", i), "zone name is required"})
			continue
		}

		if !validDomainRE.MatchString(z.Name) {
			errs = append(errs, configError{fmt.Sprintf("zones[%s]", z.Name), fmt.Sprintf("invalid domain name %q", z.Name)})
		}

		if existingIdx, ok := zoneNames[z.Name]; ok {
			errs = append(errs, configError{fmt.Sprintf("zones[%s]", z.Name), fmt.Sprintf("duplicate zone name (also at index %d)", existingIdx)})
		}
		zoneNames[z.Name] = i

		if len(z.Records) == 0 && (z.Views == nil || len(z.Views) == 0) {
			errs = append(errs, configError{fmt.Sprintf("zones[%s]", z.Name), "no records defined"})
		}

		if z.DNSSEC != nil && z.DNSSEC.Enabled {
			if z.DNSSEC.Algorithm != "" {
				validAlgos := map[string]bool{"ecdsa-p256": true, "ecdsa-p384": true, "rsa-sha256": true}
				if !validAlgos[z.DNSSEC.Algorithm] {
					errs = append(errs, configError{fmt.Sprintf("zones[%s].dnssec.algorithm", z.Name), fmt.Sprintf("invalid algorithm %q", z.DNSSEC.Algorithm)})
				}
			}
		}
	}

	return errs
}

func validateACLs(cfg Config) []error {
	var errs []error

	for i, a := range cfg.ACLs {
		if a.Name == "" {
			errs = append(errs, configError{fmt.Sprintf("acls[%d]", i), "ACL name is required"})
			continue
		}

		if !validACLActions[a.Action] && a.Action != "" {
			errs = append(errs, configError{fmt.Sprintf("acls[%s]", a.Name), fmt.Sprintf("invalid action %q (must be allow/refuse/drop/route)", a.Action)})
		}

		if a.Subnet != "" {
			if _, _, err := net.ParseCIDR(a.Subnet); err != nil {
				errs = append(errs, configError{fmt.Sprintf("acls[%s]", a.Name), fmt.Sprintf("invalid subnet %q: %v", a.Subnet, err)})
			}
		}
	}

	return errs
}

func validateDHCP(cfg Config) []error {
	var errs []error

	if cfg.DHCP.LeaseFile != "" && !cfg.DHCP.Enabled {
		errs = append(errs, configError{"dhcp.lease_file", "lease_file is set but dhcp.enabled is false"})
	}
	if cfg.DHCP.Enabled && cfg.DHCP.LeaseFile == "" {
		errs = append(errs, configError{"dhcp.lease_file", "dhcp is enabled but lease_file is not set"})
	}
	if cfg.DHCP.Format != "" && !validDHCPFormats[cfg.DHCP.Format] {
		errs = append(errs, configError{"dhcp.format", fmt.Sprintf("must be one of: dnsmasq; got %q", cfg.DHCP.Format)})
	}
	if cfg.DHCP.PollInterval < 1 {
		errs = append(errs, configError{"dhcp.poll_interval", "must be at least 1 second"})
	}

	return errs
}

func validateLogging(cfg Config) []error {
	var errs []error

	if cfg.LogLevel != "" && !validLogLevels[cfg.LogLevel] {
		errs = append(errs, configError{"log_level", fmt.Sprintf("must be one of: debug, info, warn, error; got %q", cfg.LogLevel)})
	}
	if cfg.LogMode != "" && !validLogModes[cfg.LogMode] {
		errs = append(errs, configError{"log_mode", fmt.Sprintf("must be one of: dev, prod; got %q", cfg.LogMode)})
	}
	if cfg.LogRetention < 0 {
		errs = append(errs, configError{"log_retention", "cannot be negative"})
	}

	return errs
}

func validateTracing(cfg Config) []error {
	var errs []error

	if cfg.Tracing.SampleRate < 0 || cfg.Tracing.SampleRate > 1.0 {
		errs = append(errs, configError{"tracing.sample_rate", fmt.Sprintf("must be between 0.0 and 1.0, got %f", cfg.Tracing.SampleRate)})
	}

	return errs
}

func validateHooks(cfg Config) []error {
	var errs []error

	if cfg.Hooks.RateLimiting.Rate > 0 || cfg.Hooks.RateLimiting.Enabled {
		if !validRateLimitActions[cfg.Hooks.RateLimiting.Action] {
			errs = append(errs, configError{"hooks.rate_limiting.action", fmt.Sprintf("must be one of: servfail, drop; got %q", cfg.Hooks.RateLimiting.Action)})
		}
	}

	if cfg.Hooks.TokenBucket.Rate > 0 || cfg.Hooks.TokenBucket.Enabled {
		if !validRateLimitActions[cfg.Hooks.TokenBucket.Action] {
			errs = append(errs, configError{"hooks.token_bucket.action", fmt.Sprintf("must be one of: servfail, drop; got %q", cfg.Hooks.TokenBucket.Action)})
		}
		if !validTokenBucketModes[cfg.Hooks.TokenBucket.Mode] {
			errs = append(errs, configError{"hooks.token_bucket.mode", fmt.Sprintf("must be one of: memory, valkey; got %q", cfg.Hooks.TokenBucket.Mode)})
		}
	}

	if cfg.Hooks.ResponseRateLimiting.Rate > 0 || cfg.Hooks.ResponseRateLimiting.Enabled {
		if !validRRLActions[cfg.Hooks.ResponseRateLimiting.Action] {
			errs = append(errs, configError{"hooks.response_rate_limiting.action", fmt.Sprintf("must be one of: drop, truncate; got %q", cfg.Hooks.ResponseRateLimiting.Action)})
		}
	}

	if cfg.Hooks.Blocking.Enabled || len(cfg.Hooks.Blocking.Blocklists) > 0 || len(cfg.Hooks.Blocking.RPZ) > 0 {
		if !validBlockActions[cfg.Hooks.Blocking.BlockAction] {
			errs = append(errs, configError{"hooks.blocking.block_action", fmt.Sprintf("must be one of: nxdomain, sinkhole, refused, drop; got %q", cfg.Hooks.Blocking.BlockAction)})
		}
	}

	if cfg.Hooks.AnyQuery.Enabled {
		if !validAnyQueryActions[cfg.Hooks.AnyQuery.Action] {
			errs = append(errs, configError{"hooks.any_query.action", fmt.Sprintf("must be one of: minimal, forward; got %q", cfg.Hooks.AnyQuery.Action)})
		}
	}

	if cfg.Hooks.Dnssec.Enabled {
		if !validDnssecValidationModes[cfg.Hooks.Dnssec.Validation] {
			errs = append(errs, configError{"hooks.dnssec.validation", fmt.Sprintf("must be one of: required, opportunistic; got %q", cfg.Hooks.Dnssec.Validation)})
		}
	}

	if cfg.EDNSPaddingBlockSize > 0 {
		if cfg.EDNSPaddingBlockSize&(cfg.EDNSPaddingBlockSize-1) != 0 {
			errs = append(errs, configError{"edns.padding_block_size", "must be a power of 2 (e.g., 0, 128, 256) or 0 to disable"})
		}
	}

	if _, ok := os.LookupEnv("NORTHSTAR_DNS_NEGATIVE_TTL_CAP"); ok {
		errs = append(errs, configError{"env:NORTHSTAR_DNS_NEGATIVE_TTL_CAP", "deprecated: use NORTHSTAR_DNS_NEGATIVE_TTL instead"})
	}

	return errs
}

func ValidateAndExit() int {
	errs := Validate()
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "Error: %s\n", e.Error())
		}
		return 1
	}
	fmt.Println("Config is valid")
	return 0
}
