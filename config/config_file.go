// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package config

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

type FileRPZConfig struct {
	Path   *string `yaml:"path"`
	Action *string `yaml:"action"`
}

type FileBlockingHookConfig struct {
	Enabled      *bool           `yaml:"enabled"`
	Priority     *int            `yaml:"priority"`
	BlockAction  *string         `yaml:"block_action"`
	SinkholeAddr *string         `yaml:"sinkhole_addr"`
	Blocklists   []string        `yaml:"blocklists"`
	Allowlists   []string        `yaml:"allowlists"`
	DomainRPS    *int            `yaml:"domain_rps"`
	RPZ          []FileRPZConfig `yaml:"rpz"`
}

type FileTLSConfig struct {
	CertFile       *string `yaml:"cert_file"`
	KeyFile        *string `yaml:"key_file"`
	CAFile         *string `yaml:"ca_file"`
	MinVersion     *string `yaml:"min_version"`
	AutoSelfSigned *bool   `yaml:"auto_self_signed"`
}

type FileQMinimizerHookConfig struct {
	Enabled    *bool `yaml:"enabled"`
	Priority   *int  `yaml:"priority"`
	KeepLabels *int  `yaml:"keep_labels"`
}

type FileAnyQueryHookConfig struct {
	Enabled  *bool   `yaml:"enabled"`
	Priority *int    `yaml:"priority"`
	Action   *string `yaml:"action"`
}

type FileDns64HookConfig struct {
	Enabled  *bool   `yaml:"enabled"`
	Priority *int    `yaml:"priority"`
	Prefix   *string `yaml:"prefix"`
}

type FileEcsHookConfig struct {
	Enabled  *bool `yaml:"enabled"`
	Priority *int  `yaml:"priority"`
	PrefixV4 *int  `yaml:"prefix_v4"`
	PrefixV6 *int  `yaml:"prefix_v6"`
}

type FileDnssecHookConfig struct {
	Enabled     *bool   `yaml:"enabled"`
	Priority    *int    `yaml:"priority"`
	Validation  *string `yaml:"validation"`
	TrustAnchor *string `yaml:"trust_anchor"`
}

type FileHookConfig struct {
	RateLimiting FileRateLimitHookConfig   `yaml:"rate_limiting"`
	Blocking     *FileBlockingHookConfig   `yaml:"blocking"`
	QMinimizer   *FileQMinimizerHookConfig `yaml:"qminimizer"`
	AnyQuery     *FileAnyQueryHookConfig   `yaml:"any_query"`
	Dns64        *FileDns64HookConfig      `yaml:"dns64"`
	ECS          *FileEcsHookConfig        `yaml:"ecs"`
	Dnssec       *FileDnssecHookConfig     `yaml:"dnssec"`
}

type FileRateLimitHookConfig struct {
	Enabled  *bool   `yaml:"enabled"`
	Priority *int    `yaml:"priority"`
	Rate     *int    `yaml:"rate"`
	Action   *string `yaml:"action"`
}

type FileUpstreamConfig struct {
	Name                  *string  `yaml:"name"`
	Address               *string  `yaml:"address"`
	Priority              *int     `yaml:"priority"`
	Timeout               *int     `yaml:"timeout"`
	TCPOnly               *bool    `yaml:"tcp_only"`
	TLS                   *bool    `yaml:"tls"`
	TLSServerName         *string  `yaml:"tls_server_name"`
	DoHURL                *string  `yaml:"doh_url"`
	DoQ                   *bool    `yaml:"doq"`
	HealthCheck           *bool    `yaml:"health_check"`
	HealthInterval        *int     `yaml:"health_interval"`
	HealthTimeout         *int     `yaml:"health_timeout"`
	MaxFails              *int     `yaml:"max_fails"`
	Weight                *int     `yaml:"weight"`
	AdaptiveTimeoutFactor *float64 `yaml:"adaptive_timeout_factor"`
}

type FileConditionalRouteConfig struct {
	Domain   *string `yaml:"domain"`
	Upstream *string `yaml:"upstream"`
}

type FileZoneRecordConfig struct {
	Name string  `yaml:"name"`
	Type string  `yaml:"type"`
	TTL  *uint32 `yaml:"ttl,omitempty"`

	IP         *string `yaml:"ip,omitempty"`
	Target     *string `yaml:"target,omitempty"`
	Preference *uint16 `yaml:"preference,omitempty"`
	Host       *string `yaml:"host,omitempty"`

	MName   *string `yaml:"mname,omitempty"`
	RName   *string `yaml:"rname,omitempty"`
	Serial  *uint32 `yaml:"serial,omitempty"`
	Refresh *uint32 `yaml:"refresh,omitempty"`
	Retry   *uint32 `yaml:"retry,omitempty"`
	Expire  *uint32 `yaml:"expire,omitempty"`
	Minimum *uint32 `yaml:"minimum,omitempty"`

	SRVPriority *uint16 `yaml:"srv_priority,omitempty"`
	SRVWeight   *uint16 `yaml:"srv_weight,omitempty"`
	SRVPort     *uint16 `yaml:"srv_port,omitempty"`
	SRVTarget   *string `yaml:"srv_target,omitempty"`

	TXTData *string `yaml:"txt_data,omitempty"`

	DNSKEYFlags     *uint16 `yaml:"dnskey_flags,omitempty"`
	DNSKEYAlgorithm *uint8  `yaml:"dnskey_algorithm,omitempty"`
	DNSKEYPublicKey *string `yaml:"dnskey_public_key,omitempty"`

	RRSIGTypeCovered *uint16 `yaml:"rrsig_type_covered,omitempty"`
	RRSIGAlgorithm   *uint8  `yaml:"rrsig_algorithm,omitempty"`
	RRSIGLabels      *uint8  `yaml:"rrsig_labels,omitempty"`
	RRSIGOriginalTTL *uint32 `yaml:"rrsig_original_ttl,omitempty"`
	RRSIGExpiration  *uint32 `yaml:"rrsig_expiration,omitempty"`
	RRSIGInception   *uint32 `yaml:"rrsig_inception,omitempty"`
	RRSIGKeyTag      *uint16 `yaml:"rrsig_key_tag,omitempty"`
	RRSIGSignerName  *string `yaml:"rrsig_signer_name,omitempty"`
	RRSIGSignature   *string `yaml:"rrsig_signature,omitempty"`

	NSECNextDomain *string   `yaml:"nsec_next_domain,omitempty"`
	NSECTypes      *[]uint16 `yaml:"nsec_types,omitempty"`
}

type FileZoneDNSSECConfig struct {
	Enabled   *bool   `yaml:"enabled"`
	Algorithm *string `yaml:"algorithm"`
	KeyFile   *string `yaml:"key_file,omitempty"`
	ZSKFile   *string `yaml:"zsk_file,omitempty"`
	NSEC3     *bool   `yaml:"nsec3,omitempty"`
}

type FileZoneConfig struct {
	Name    *string                `yaml:"name"`
	Records []FileZoneRecordConfig `yaml:"records,omitempty"`
	DNSSEC  *FileZoneDNSSECConfig  `yaml:"dnssec,omitempty"`
}

type FileACLConfig struct {
	Name     *string `yaml:"name"`
	Action   *string `yaml:"action"`
	Subnet   *string `yaml:"subnet,omitempty"`
	Zone     *string `yaml:"zone,omitempty"`
	Protocol *string `yaml:"protocol,omitempty"`
	Upstream *string `yaml:"upstream,omitempty"`
}

type FileConfig struct {
	Mode                 *string                      `yaml:"mode"`
	DNSPort              *int                         `yaml:"dns_port"`
	UpstreamAddr         *string                      `yaml:"upstream"`
	Upstreams            []FileUpstreamConfig         `yaml:"upstreams"`
	ConditionalRoutes    []FileConditionalRouteConfig `yaml:"conditional_routes"`
	UpstreamConcurrency  *int                         `yaml:"upstream_concurrency"`
	CacheAddr            *string                      `yaml:"cache_addr"`
	CacheFile            *string                      `yaml:"cache_file"`
	Ipv4Disable          *bool                        `yaml:"ipv4_disable"`
	Ipv6Disable          *bool                        `yaml:"ipv6_disable"`
	TcpDisable           *bool                        `yaml:"tcp_disable"`
	RateLimit            *int                         `yaml:"rate_limit"`
	StaleAge             *int                         `yaml:"stale_age"`
	NegativeTTL          *int                         `yaml:"negative_ttl"`
	CacheWarmup          *bool                        `yaml:"cache_warmup"`
	CacheMaxEntries      *int                         `yaml:"cache_max_entries"`
	TTLMin               *int                         `yaml:"ttl_min"`
	TTLMax               *int                         `yaml:"ttl_max"`
	UpstreamPoolSize     *int                         `yaml:"upstream_pool_size"`
	UpstreamPoolIdle     *int                         `yaml:"upstream_pool_idle"`
	LogLevel             *string                      `yaml:"log_level"`
	LogMode              *string                      `yaml:"log_mode"`
	LogDir               *string                      `yaml:"log_dir"`
	LogRetention         *int                         `yaml:"log_retention"`
	TimeZone             *string                      `yaml:"timezone"`
	MaxTCPConnsPerClient *int                         `yaml:"max_tcp_conns_per_client"`
	MetricsEnable        *bool                        `yaml:"metrics_enable"`
	MetricsPort          *int                         `yaml:"metrics_port"`
	APIEnable            *bool                        `yaml:"api_enable"`
	APIPort              *int                         `yaml:"api_port"`
	APIKey               *string                      `yaml:"api_key"`
	DoTEnabled           *bool                        `yaml:"dot_enabled"`
	DoTPort              *int                         `yaml:"dot_port"`
	DoHEnabled           *bool                        `yaml:"doh_enabled"`
	DoHPort              *int                         `yaml:"doh_port"`
	DoQEnabled           *bool                        `yaml:"doq_enabled"`
	DoQPort              *int                         `yaml:"doq_port"`
	Dns64Prefix          *string                      `yaml:"dns64_prefix"`
	EcsPrefixV4          *int                         `yaml:"ecs_prefix_v4"`
	EcsPrefixV6          *int                         `yaml:"ecs_prefix_v6"`
	TLS                  *FileTLSConfig               `yaml:"tls"`
	Zones                []FileZoneConfig             `yaml:"zones,omitempty"`
	ACLs                 []FileACLConfig              `yaml:"acls,omitempty"`
	Hooks                *FileHookConfig              `yaml:"hooks"`
}

func loadFile(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fc FileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &fc, nil
}

func fileUpstreamToConfig(src *FileUpstreamConfig) UpstreamConfig {
	var dst UpstreamConfig
	if src.Name != nil {
		dst.Name = *src.Name
	}
	if src.Address != nil {
		dst.Address = *src.Address
	}
	if src.Priority != nil {
		dst.Priority = *src.Priority
	}
	if src.Timeout != nil {
		dst.Timeout = *src.Timeout
	}
	if src.TCPOnly != nil {
		dst.TCPOnly = *src.TCPOnly
	}
	if src.TLS != nil {
		dst.TLS = *src.TLS
	}
	if src.TLSServerName != nil {
		dst.TLSServerName = *src.TLSServerName
	}
	if src.DoHURL != nil {
		dst.DoHURL = *src.DoHURL
	}
	if src.DoQ != nil {
		dst.DoQ = *src.DoQ
	}
	if src.HealthCheck != nil {
		dst.HealthCheck = *src.HealthCheck
	}
	if src.HealthInterval != nil {
		dst.HealthInterval = *src.HealthInterval
	}
	if src.HealthTimeout != nil {
		dst.HealthTimeout = *src.HealthTimeout
	}
	if src.MaxFails != nil {
		dst.MaxFails = *src.MaxFails
	}
	if src.Weight != nil {
		dst.Weight = *src.Weight
	}
	if src.AdaptiveTimeoutFactor != nil {
		dst.AdaptiveTimeoutFactor = *src.AdaptiveTimeoutFactor
	}
	return dst
}

func applyFileConfig(cfg *Config, fc *FileConfig) {
	if fc.Mode != nil {
		cfg.Mode = *fc.Mode
	}
	if fc.DNSPort != nil {
		cfg.DNSPort = *fc.DNSPort
	}
	if fc.UpstreamAddr != nil {
		cfg.UpstreamAddr = *fc.UpstreamAddr
	}
	if len(fc.Upstreams) > 0 {
		cfg.Upstreams = make([]UpstreamConfig, len(fc.Upstreams))
		for i := range fc.Upstreams {
			cfg.Upstreams[i] = fileUpstreamToConfig(&fc.Upstreams[i])
		}
	}
	if len(fc.ConditionalRoutes) > 0 {
		cfg.ConditionalRoutes = make([]ConditionalRouteConfig, len(fc.ConditionalRoutes))
		for i := range fc.ConditionalRoutes {
			if fc.ConditionalRoutes[i].Domain != nil {
				cfg.ConditionalRoutes[i].Domain = *fc.ConditionalRoutes[i].Domain
			}
			if fc.ConditionalRoutes[i].Upstream != nil {
				cfg.ConditionalRoutes[i].Upstream = *fc.ConditionalRoutes[i].Upstream
			}
		}
	}

	if fc.CacheAddr != nil {
		cfg.CacheAddr = *fc.CacheAddr
	}
	if fc.CacheFile != nil {
		cfg.CacheFile = *fc.CacheFile
	}
	if fc.Ipv4Disable != nil {
		cfg.Ipv4Disable = *fc.Ipv4Disable
	}
	if fc.Ipv6Disable != nil {
		cfg.Ipv6Disable = *fc.Ipv6Disable
	}
	if fc.TcpDisable != nil {
		cfg.TcpDisable = *fc.TcpDisable
	}
	if fc.RateLimit != nil {
		cfg.RateLimit = *fc.RateLimit
	}
	if fc.StaleAge != nil {
		cfg.StaleAge = *fc.StaleAge
	}
	if fc.NegativeTTL != nil {
		cfg.NegativeTTL = *fc.NegativeTTL
	}
	if fc.CacheWarmup != nil {
		cfg.CacheWarmup = *fc.CacheWarmup
	}
	if fc.CacheMaxEntries != nil {
		cfg.CacheMaxEntries = *fc.CacheMaxEntries
	}
	if fc.TTLMin != nil {
		cfg.TTLMin = *fc.TTLMin
	}
	if fc.TTLMax != nil {
		cfg.TTLMax = *fc.TTLMax
	}
	if fc.UpstreamPoolSize != nil {
		cfg.UpstreamPoolSize = *fc.UpstreamPoolSize
	}
	if fc.UpstreamPoolIdle != nil {
		cfg.UpstreamPoolIdle = *fc.UpstreamPoolIdle
	}
	if fc.UpstreamConcurrency != nil {
		cfg.UpstreamConcurrency = *fc.UpstreamConcurrency
	}
	if fc.LogLevel != nil {
		cfg.LogLevel = *fc.LogLevel
	}
	if fc.LogMode != nil {
		cfg.LogMode = *fc.LogMode
	}
	if fc.LogDir != nil {
		cfg.LogDir = *fc.LogDir
	}
	if fc.LogRetention != nil {
		cfg.LogRetention = *fc.LogRetention
	}
	if fc.TimeZone != nil {
		cfg.TimeZone = *fc.TimeZone
	}
	if fc.MaxTCPConnsPerClient != nil {
		cfg.MaxTCPConnsPerClient = *fc.MaxTCPConnsPerClient
	}
	if fc.MetricsEnable != nil {
		cfg.MetricsEnable = *fc.MetricsEnable
	}
	if fc.MetricsPort != nil {
		cfg.MetricsPort = *fc.MetricsPort
	}
	if fc.APIEnable != nil {
		cfg.APIEnable = *fc.APIEnable
	}
	if fc.APIPort != nil {
		cfg.APIPort = *fc.APIPort
	}
	if fc.APIKey != nil {
		cfg.APIKey = *fc.APIKey
	}
	if fc.DoTEnabled != nil {
		cfg.DoTEnabled = *fc.DoTEnabled
	}
	if fc.DoTPort != nil {
		cfg.DoTPort = *fc.DoTPort
	}
	if fc.DoHEnabled != nil {
		cfg.DoHEnabled = *fc.DoHEnabled
	}
	if fc.DoHPort != nil {
		cfg.DoHPort = *fc.DoHPort
	}
	if fc.DoQEnabled != nil {
		cfg.DoQEnabled = *fc.DoQEnabled
	}
	if fc.DoQPort != nil {
		cfg.DoQPort = *fc.DoQPort
	}
	if fc.TLS != nil {
		if fc.TLS.CertFile != nil {
			cfg.TLS.CertFile = *fc.TLS.CertFile
		}
		if fc.TLS.KeyFile != nil {
			cfg.TLS.KeyFile = *fc.TLS.KeyFile
		}
		if fc.TLS.CAFile != nil {
			cfg.TLS.CAFile = *fc.TLS.CAFile
		}
		if fc.TLS.MinVersion != nil {
			cfg.TLS.MinVersion = *fc.TLS.MinVersion
		}
		if fc.TLS.AutoSelfSigned != nil {
			cfg.TLS.AutoSelfSigned = *fc.TLS.AutoSelfSigned
		}
	}
	if fc.Dns64Prefix != nil {
		cfg.Dns64Prefix = *fc.Dns64Prefix
	}
	if fc.EcsPrefixV4 != nil {
		cfg.EcsPrefixV4 = *fc.EcsPrefixV4
	}
	if fc.EcsPrefixV6 != nil {
		cfg.EcsPrefixV6 = *fc.EcsPrefixV6
	}
	if fc.Hooks != nil {
		if fc.Hooks.RateLimiting.Enabled != nil {
			cfg.Hooks.RateLimiting.Enabled = *fc.Hooks.RateLimiting.Enabled
		}
		if fc.Hooks.RateLimiting.Priority != nil {
			cfg.Hooks.RateLimiting.Priority = *fc.Hooks.RateLimiting.Priority
		}
		if fc.Hooks.RateLimiting.Rate != nil {
			cfg.Hooks.RateLimiting.Rate = *fc.Hooks.RateLimiting.Rate
		}
		if fc.Hooks.RateLimiting.Action != nil {
			cfg.Hooks.RateLimiting.Action = *fc.Hooks.RateLimiting.Action
		}
		if fc.Hooks.QMinimizer != nil {
			if fc.Hooks.QMinimizer.Enabled != nil {
				cfg.Hooks.QMinimizer.Enabled = *fc.Hooks.QMinimizer.Enabled
			}
			if fc.Hooks.QMinimizer.Priority != nil {
				cfg.Hooks.QMinimizer.Priority = *fc.Hooks.QMinimizer.Priority
			}
			if fc.Hooks.QMinimizer.KeepLabels != nil {
				cfg.Hooks.QMinimizer.KeepLabels = *fc.Hooks.QMinimizer.KeepLabels
			}
		}
		if fc.Hooks.Blocking != nil {
			if fc.Hooks.Blocking.Enabled != nil {
				cfg.Hooks.Blocking.Enabled = *fc.Hooks.Blocking.Enabled
			}
			if fc.Hooks.Blocking.Priority != nil {
				cfg.Hooks.Blocking.Priority = *fc.Hooks.Blocking.Priority
			}
			if fc.Hooks.Blocking.BlockAction != nil {
				cfg.Hooks.Blocking.BlockAction = *fc.Hooks.Blocking.BlockAction
			}
			if fc.Hooks.Blocking.SinkholeAddr != nil {
				cfg.Hooks.Blocking.SinkholeAddr = *fc.Hooks.Blocking.SinkholeAddr
			}
			if len(fc.Hooks.Blocking.Blocklists) > 0 {
				cfg.Hooks.Blocking.Blocklists = fc.Hooks.Blocking.Blocklists
			}
			if len(fc.Hooks.Blocking.Allowlists) > 0 {
				cfg.Hooks.Blocking.Allowlists = fc.Hooks.Blocking.Allowlists
			}
			if fc.Hooks.Blocking.DomainRPS != nil {
				cfg.Hooks.Blocking.DomainRPS = *fc.Hooks.Blocking.DomainRPS
			}
			if len(fc.Hooks.Blocking.RPZ) > 0 {
				cfg.Hooks.Blocking.RPZ = make([]RPZConfig, len(fc.Hooks.Blocking.RPZ))
				for i, r := range fc.Hooks.Blocking.RPZ {
					if r.Path != nil {
						cfg.Hooks.Blocking.RPZ[i].Path = *r.Path
					}
					if r.Action != nil {
						cfg.Hooks.Blocking.RPZ[i].Action = *r.Action
					}
				}
			}
		}
		if fc.Hooks.AnyQuery != nil {
			if fc.Hooks.AnyQuery.Enabled != nil {
				cfg.Hooks.AnyQuery.Enabled = *fc.Hooks.AnyQuery.Enabled
			}
			if fc.Hooks.AnyQuery.Priority != nil {
				cfg.Hooks.AnyQuery.Priority = *fc.Hooks.AnyQuery.Priority
			}
			if fc.Hooks.AnyQuery.Action != nil {
				cfg.Hooks.AnyQuery.Action = *fc.Hooks.AnyQuery.Action
			}
		}
		if fc.Hooks.Dns64 != nil {
			if fc.Hooks.Dns64.Enabled != nil {
				cfg.Hooks.Dns64.Enabled = *fc.Hooks.Dns64.Enabled
			}
			if fc.Hooks.Dns64.Priority != nil {
				cfg.Hooks.Dns64.Priority = *fc.Hooks.Dns64.Priority
			}
			if fc.Hooks.Dns64.Prefix != nil {
				cfg.Hooks.Dns64.Prefix = *fc.Hooks.Dns64.Prefix
				cfg.Dns64Prefix = *fc.Hooks.Dns64.Prefix
			}
		}
		if fc.Hooks.ECS != nil {
			if fc.Hooks.ECS.Enabled != nil {
				cfg.Hooks.ECS.Enabled = *fc.Hooks.ECS.Enabled
			}
			if fc.Hooks.ECS.Priority != nil {
				cfg.Hooks.ECS.Priority = *fc.Hooks.ECS.Priority
			}
			if fc.Hooks.ECS.PrefixV4 != nil {
				cfg.Hooks.ECS.PrefixV4 = *fc.Hooks.ECS.PrefixV4
			}
			if fc.Hooks.ECS.PrefixV6 != nil {
				cfg.Hooks.ECS.PrefixV6 = *fc.Hooks.ECS.PrefixV6
			}
		}
		if fc.Hooks.Dnssec != nil {
			if fc.Hooks.Dnssec.Enabled != nil {
				cfg.Hooks.Dnssec.Enabled = *fc.Hooks.Dnssec.Enabled
			}
			if fc.Hooks.Dnssec.Priority != nil {
				cfg.Hooks.Dnssec.Priority = *fc.Hooks.Dnssec.Priority
			}
			if fc.Hooks.Dnssec.Validation != nil {
				cfg.Hooks.Dnssec.Validation = *fc.Hooks.Dnssec.Validation
			}
			if fc.Hooks.Dnssec.TrustAnchor != nil {
				cfg.Hooks.Dnssec.TrustAnchor = *fc.Hooks.Dnssec.TrustAnchor
			}
		}
	}
}

func fileACLToConfig(fa FileACLConfig) ACLConfig {
	ac := ACLConfig{}
	if fa.Name != nil {
		ac.Name = *fa.Name
	}
	if fa.Action != nil {
		ac.Action = *fa.Action
	}
	if fa.Subnet != nil {
		ac.Subnet = *fa.Subnet
	}
	if fa.Zone != nil {
		ac.Zone = *fa.Zone
	}
	if fa.Protocol != nil {
		ac.Protocol = *fa.Protocol
	}
	if fa.Upstream != nil {
		ac.Upstream = *fa.Upstream
	}
	return ac
}

func fileZoneRecordToConfig(fr FileZoneRecordConfig) ZoneRecordConfig {
	zc := ZoneRecordConfig{
		Name: fr.Name,
		Type: fr.Type,
	}
	if fr.TTL != nil {
		zc.TTL = *fr.TTL
	}
	zc.IP = fr.IP
	zc.Target = fr.Target
	zc.Preference = fr.Preference
	zc.Host = fr.Host
	zc.MName = fr.MName
	zc.RName = fr.RName
	zc.Serial = fr.Serial
	zc.Refresh = fr.Refresh
	zc.Retry = fr.Retry
	zc.Expire = fr.Expire
	zc.Minimum = fr.Minimum
	zc.SRVPriority = fr.SRVPriority
	zc.SRVWeight = fr.SRVWeight
	zc.SRVPort = fr.SRVPort
	zc.SRVTarget = fr.SRVTarget
	zc.TXTData = fr.TXTData
	zc.DNSKEYFlags = fr.DNSKEYFlags
	zc.DNSKEYAlgorithm = fr.DNSKEYAlgorithm
	zc.DNSKEYPublicKey = fr.DNSKEYPublicKey
	zc.RRSIGTypeCovered = fr.RRSIGTypeCovered
	zc.RRSIGAlgorithm = fr.RRSIGAlgorithm
	zc.RRSIGLabels = fr.RRSIGLabels
	zc.RRSIGOriginalTTL = fr.RRSIGOriginalTTL
	zc.RRSIGExpiration = fr.RRSIGExpiration
	zc.RRSIGInception = fr.RRSIGInception
	zc.RRSIGKeyTag = fr.RRSIGKeyTag
	zc.RRSIGSignerName = fr.RRSIGSignerName
	zc.RRSIGSignature = fr.RRSIGSignature
	zc.NSECNextDomain = fr.NSECNextDomain
	zc.NSECTypes = fr.NSECTypes
	return zc
}
func configToFile(cfg *Config) *FileConfig {
	mode := cfg.Mode
	dnsPort := cfg.DNSPort
	upstream := cfg.UpstreamAddr
	cacheAddr := cfg.CacheAddr
	cacheFile := cfg.CacheFile
	ipv4Disable := cfg.Ipv4Disable
	ipv6Disable := cfg.Ipv6Disable
	tcpDisable := cfg.TcpDisable
	tls := cfg.TLS
	rateLimit := cfg.RateLimit
	staleAge := cfg.StaleAge
	negativeTTL := cfg.NegativeTTL
	cacheWarmup := cfg.CacheWarmup
	cacheMaxEntries := cfg.CacheMaxEntries
	ttlMin := cfg.TTLMin
	ttlMax := cfg.TTLMax
	upstreamPoolSize := cfg.UpstreamPoolSize
	upstreamPoolIdle := cfg.UpstreamPoolIdle
	upstreamConcurrency := cfg.UpstreamConcurrency
	logLevel := cfg.LogLevel
	logMode := cfg.LogMode
	logDir := cfg.LogDir
	logRetention := cfg.LogRetention
	timeZone := cfg.TimeZone
	maxTCPConnsPerClient := cfg.MaxTCPConnsPerClient
	metricsEnable := cfg.MetricsEnable
	metricsPort := cfg.MetricsPort
	apiEnable := cfg.APIEnable
	apiPort := cfg.APIPort
	apiKey := cfg.APIKey
	dotEnabled := cfg.DoTEnabled
	dotPort := cfg.DoTPort
	dohEnabled := cfg.DoHEnabled
	dohPort := cfg.DoHPort
	doqEnabled := cfg.DoQEnabled
	doqPort := cfg.DoQPort
	dns64Prefix := cfg.Dns64Prefix
	ecsPrefixV4 := cfg.EcsPrefixV4
	ecsPrefixV6 := cfg.EcsPrefixV6
	hookEnabled := cfg.Hooks.RateLimiting.Enabled
	hookPriority := cfg.Hooks.RateLimiting.Priority
	hookRate := cfg.Hooks.RateLimiting.Rate
	hookAction := cfg.Hooks.RateLimiting.Action

	blockingEnabled := cfg.Hooks.Blocking.Enabled
	blockingPriority := cfg.Hooks.Blocking.Priority
	blockingAction := cfg.Hooks.Blocking.BlockAction
	blockingSinkhole := cfg.Hooks.Blocking.SinkholeAddr
	blockingLists := cfg.Hooks.Blocking.Blocklists
	blockingAllowlists := cfg.Hooks.Blocking.Allowlists
	blockingDomainRPS := cfg.Hooks.Blocking.DomainRPS

	qminEnabled := cfg.Hooks.QMinimizer.Enabled
	qminPriority := cfg.Hooks.QMinimizer.Priority
	qminKeepLabels := cfg.Hooks.QMinimizer.KeepLabels

	anyQueryEnabled := cfg.Hooks.AnyQuery.Enabled
	anyQueryPriority := cfg.Hooks.AnyQuery.Priority
	anyQueryAction := cfg.Hooks.AnyQuery.Action

	dns64HookEnabled := cfg.Hooks.Dns64.Enabled
	dns64HookPriority := cfg.Hooks.Dns64.Priority
	dns64HookPrefix := cfg.Hooks.Dns64.Prefix

	ecsHookEnabled := cfg.Hooks.ECS.Enabled
	ecsHookPriority := cfg.Hooks.ECS.Priority
	ecsHookPrefixV4 := cfg.Hooks.ECS.PrefixV4
	ecsHookPrefixV6 := cfg.Hooks.ECS.PrefixV6

	dnssecEnabled := cfg.Hooks.Dnssec.Enabled
	dnssecPriority := cfg.Hooks.Dnssec.Priority
	dnssecValidation := cfg.Hooks.Dnssec.Validation
	dnssecTrustAnchor := cfg.Hooks.Dnssec.TrustAnchor

	var fileUpstreams []FileUpstreamConfig
	for _, u := range cfg.Upstreams {
		name := u.Name
		addr := u.Address
		priority := u.Priority
		timeout := u.Timeout
		tcpOnly := u.TCPOnly
		healthCheck := u.HealthCheck
		healthInterval := u.HealthInterval
		healthTimeout := u.HealthTimeout
		maxFails := u.MaxFails
		weight := u.Weight
		adaptiveFactor := u.AdaptiveTimeoutFactor
		fileUpstreams = append(fileUpstreams, FileUpstreamConfig{
			Name:                  &name,
			Address:               &addr,
			Priority:              &priority,
			Timeout:               &timeout,
			TCPOnly:               &tcpOnly,
			HealthCheck:           &healthCheck,
			HealthInterval:        &healthInterval,
			HealthTimeout:         &healthTimeout,
			MaxFails:              &maxFails,
			Weight:                &weight,
			AdaptiveTimeoutFactor: &adaptiveFactor,
		})
	}

	var fileRPZ []FileRPZConfig
	for _, r := range cfg.Hooks.Blocking.RPZ {
		path := r.Path
		action := r.Action
		fileRPZ = append(fileRPZ, FileRPZConfig{
			Path:   &path,
			Action: &action,
		})
	}

	var fileRoutes []FileConditionalRouteConfig
	for _, r := range cfg.ConditionalRoutes {
		domain := r.Domain
		upstreamName := r.Upstream
		fileRoutes = append(fileRoutes, FileConditionalRouteConfig{
			Domain:   &domain,
			Upstream: &upstreamName,
		})
	}

	var fileZones []FileZoneConfig
	for _, z := range cfg.Zones {
		fileRecords := make([]FileZoneRecordConfig, len(z.Records))
		for i, r := range z.Records {
			fileRecords[i] = zoneRecordToFile(r)
		}
		fz := FileZoneConfig{
			Name:    &z.Name,
			Records: fileRecords,
		}
		if z.DNSSEC != nil {
			fz.DNSSEC = &FileZoneDNSSECConfig{
				Enabled:   &z.DNSSEC.Enabled,
				Algorithm: &z.DNSSEC.Algorithm,
				NSEC3:     &z.DNSSEC.NSEC3,
			}
			if z.DNSSEC.KeyFile != "" {
				fz.DNSSEC.KeyFile = &z.DNSSEC.KeyFile
			}
			if z.DNSSEC.ZSKFile != "" {
				fz.DNSSEC.ZSKFile = &z.DNSSEC.ZSKFile
			}
		}
		fileZones = append(fileZones, fz)
	}

	var fileACLs []FileACLConfig
	for _, a := range cfg.ACLs {
		fa := FileACLConfig{
			Name:   &a.Name,
			Action: &a.Action,
		}
		if a.Subnet != "" {
			fa.Subnet = &a.Subnet
		}
		if a.Zone != "" {
			fa.Zone = &a.Zone
		}
		if a.Protocol != "" {
			fa.Protocol = &a.Protocol
		}
		if a.Upstream != "" {
			fa.Upstream = &a.Upstream
		}
		fileACLs = append(fileACLs, fa)
	}

	return &FileConfig{
		Mode:                &mode,
		DNSPort:             &dnsPort,
		UpstreamAddr:        &upstream,
		Upstreams:           fileUpstreams,
		ConditionalRoutes:   fileRoutes,
		UpstreamConcurrency: &upstreamConcurrency,
		CacheAddr:           &cacheAddr,
		CacheFile:           &cacheFile,
		Ipv4Disable:         &ipv4Disable,
		Ipv6Disable:         &ipv6Disable,
		TcpDisable:          &tcpDisable,
		DoTEnabled:          &dotEnabled,
		DoTPort:             &dotPort,
		DoHEnabled:          &dohEnabled,
		DoHPort:             &dohPort,
		DoQEnabled:          &doqEnabled,
		DoQPort:             &doqPort,
		TLS: &FileTLSConfig{
			CertFile:       &tls.CertFile,
			KeyFile:        &tls.KeyFile,
			CAFile:         &tls.CAFile,
			MinVersion:     &tls.MinVersion,
			AutoSelfSigned: &tls.AutoSelfSigned,
		},
		RateLimit:            &rateLimit,
		StaleAge:             &staleAge,
		NegativeTTL:          &negativeTTL,
		CacheWarmup:          &cacheWarmup,
		CacheMaxEntries:      &cacheMaxEntries,
		TTLMin:               &ttlMin,
		TTLMax:               &ttlMax,
		UpstreamPoolSize:     &upstreamPoolSize,
		UpstreamPoolIdle:     &upstreamPoolIdle,
		LogLevel:             &logLevel,
		LogMode:              &logMode,
		LogDir:               &logDir,
		LogRetention:         &logRetention,
		TimeZone:             &timeZone,
		MaxTCPConnsPerClient: &maxTCPConnsPerClient,
		MetricsEnable:        &metricsEnable,
		MetricsPort:          &metricsPort,
		APIEnable:            &apiEnable,
		APIPort:              &apiPort,
		APIKey:               &apiKey,
		Dns64Prefix:          &dns64Prefix,
		EcsPrefixV4:          &ecsPrefixV4,
		EcsPrefixV6:          &ecsPrefixV6,
		Hooks: &FileHookConfig{
			RateLimiting: FileRateLimitHookConfig{
				Enabled:  &hookEnabled,
				Priority: &hookPriority,
				Rate:     &hookRate,
				Action:   &hookAction,
			},
			Blocking: &FileBlockingHookConfig{
				Enabled:      &blockingEnabled,
				Priority:     &blockingPriority,
				BlockAction:  &blockingAction,
				SinkholeAddr: &blockingSinkhole,
				Blocklists:   blockingLists,
				Allowlists:   blockingAllowlists,
				DomainRPS:    &blockingDomainRPS,
				RPZ:          fileRPZ,
			},
			QMinimizer: &FileQMinimizerHookConfig{
				Enabled:    &qminEnabled,
				Priority:   &qminPriority,
				KeepLabels: &qminKeepLabels,
			},
			AnyQuery: &FileAnyQueryHookConfig{
				Enabled:  &anyQueryEnabled,
				Priority: &anyQueryPriority,
				Action:   &anyQueryAction,
			},
			Dns64: &FileDns64HookConfig{
				Enabled:  &dns64HookEnabled,
				Priority: &dns64HookPriority,
				Prefix:   &dns64HookPrefix,
			},
			ECS: &FileEcsHookConfig{
				Enabled:  &ecsHookEnabled,
				Priority: &ecsHookPriority,
				PrefixV4: &ecsHookPrefixV4,
				PrefixV6: &ecsHookPrefixV6,
			},
			Dnssec: &FileDnssecHookConfig{
				Enabled:     &dnssecEnabled,
				Priority:    &dnssecPriority,
				Validation:  &dnssecValidation,
				TrustAnchor: &dnssecTrustAnchor,
			},
		},
		Zones: fileZones,
		ACLs:  fileACLs,
	}
}

func zoneRecordToFile(zc ZoneRecordConfig) FileZoneRecordConfig {
	fr := FileZoneRecordConfig{
		Name: zc.Name,
		Type: zc.Type,
	}
	if zc.TTL != 0 {
		fr.TTL = &zc.TTL
	}
	fr.IP = zc.IP
	fr.Target = zc.Target
	fr.Preference = zc.Preference
	fr.Host = zc.Host
	fr.MName = zc.MName
	fr.RName = zc.RName
	fr.Serial = zc.Serial
	fr.Refresh = zc.Refresh
	fr.Retry = zc.Retry
	fr.Expire = zc.Expire
	fr.Minimum = zc.Minimum
	fr.SRVPriority = zc.SRVPriority
	fr.SRVWeight = zc.SRVWeight
	fr.SRVPort = zc.SRVPort
	fr.SRVTarget = zc.SRVTarget
	fr.TXTData = zc.TXTData
	fr.DNSKEYFlags = zc.DNSKEYFlags
	fr.DNSKEYAlgorithm = zc.DNSKEYAlgorithm
	fr.DNSKEYPublicKey = zc.DNSKEYPublicKey
	fr.RRSIGTypeCovered = zc.RRSIGTypeCovered
	fr.RRSIGAlgorithm = zc.RRSIGAlgorithm
	fr.RRSIGLabels = zc.RRSIGLabels
	fr.RRSIGOriginalTTL = zc.RRSIGOriginalTTL
	fr.RRSIGExpiration = zc.RRSIGExpiration
	fr.RRSIGInception = zc.RRSIGInception
	fr.RRSIGKeyTag = zc.RRSIGKeyTag
	fr.RRSIGSignerName = zc.RRSIGSignerName
	fr.RRSIGSignature = zc.RRSIGSignature
	fr.NSECNextDomain = zc.NSECNextDomain
	fr.NSECTypes = zc.NSECTypes
	return fr
}

func writeFile(path string, fc *FileConfig) error {
	data, err := yaml.Marshal(fc)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	header := `# northstar configuration
#
# Environment variables override every value in this file.
# Hierarchy (highest to lowest):
#   1. NORTHSTAR_* environment variables
#   2. Values in this file
#   3. Built-in defaults
#
# To use this file: place it at ./northstar.yaml or set
# the NORTHSTAR_CONFIG env var to a custom path.
# If no config file exists, this file is auto-generated on startup.
# You only need to uncomment and change the values you want to override.

`
	return os.WriteFile(path, append([]byte(header), data...), 0644)
}

func WriteEffectiveConfig(path string, cfg *Config) error {
	return writeFile(path, configToFile(cfg))
}

func applyFileZones(cfg *Config, fc *FileConfig) {
	if fc.Zones == nil {
		return
	}
	cfg.Zones = make([]ZoneConfig, len(fc.Zones))
	for i, fz := range fc.Zones {
		cfg.Zones[i] = ZoneConfig{}
		if fz.Name != nil {
			cfg.Zones[i].Name = *fz.Name
		}
		if fz.Records != nil {
			cfg.Zones[i].Records = make([]ZoneRecordConfig, len(fz.Records))
			for j, fr := range fz.Records {
				cfg.Zones[i].Records[j] = fileZoneRecordToConfig(fr)
			}
		}
		if fz.DNSSEC != nil {
			d := &ZoneDNSSECConfig{}
			if fz.DNSSEC.Enabled != nil {
				d.Enabled = *fz.DNSSEC.Enabled
			}
			if fz.DNSSEC.Algorithm != nil {
				d.Algorithm = *fz.DNSSEC.Algorithm
			}
			if fz.DNSSEC.KeyFile != nil {
				d.KeyFile = *fz.DNSSEC.KeyFile
			}
			if fz.DNSSEC.ZSKFile != nil {
				d.ZSKFile = *fz.DNSSEC.ZSKFile
			}
			if fz.DNSSEC.NSEC3 != nil {
				d.NSEC3 = *fz.DNSSEC.NSEC3
			}
			cfg.Zones[i].DNSSEC = d
		}
	}
}

func applyFileACLs(cfg *Config, fc *FileConfig) {
	if fc.ACLs == nil {
		return
	}
	cfg.ACLs = make([]ACLConfig, len(fc.ACLs))
	for i, fa := range fc.ACLs {
		cfg.ACLs[i] = fileACLToConfig(fa)
	}
}

func WriteDefaultConfig(path string) error {
	mode := "prod"
	dnsPort := 53
	upstream := "8.8.8.8:53"
	cacheAddr := ""
	cacheFile := ""
	ipv4Disable := false
	ipv6Disable := false
	tcpDisable := false
	certFile := ""
	keyFile := ""
	caFile := ""
	tlsMinVer := "1.2"
	autoSelfSigned := true
	rateLimit := 0
	staleAge := 60
	negativeTTL := 0
	cacheWarmup := false
	cacheMaxEntries := 0
	ttlMin := 0
	ttlMax := 0
	upstreamPoolSize := 10
	upstreamPoolIdle := 30
	upstreamConcurrency := 1
	logLevel := ""
	logMode := ""
	logDir := "."
	logRetention := 7
	timeZone := ""
	maxTCPConnsPerClient := 0
	metricsEnable := false
	metricsPort := 9153
	apiEnable := false
	apiPort := 9163
	apiKey := ""
	dotEnabled := true
	dotPort := 853
	dohEnabled := true
	dohPort := 443
	doqEnabled := true
	doqPort := 853
	dns64Prefix := "64:ff9b::/96"
	ecsPrefixV4 := 24
	ecsPrefixV6 := 56
	hookEnabled := false
	hookPriority := 100
	hookRate := 0
	hookAction := "servfail"
	blockingEnabled := false
	blockingPriority := 200
	blockingAction := "nxdomain"
	blockingSinkhole := "127.0.0.1"
	blockingDomainRPS := 0
	qminEnabled := false
	qminPriority := 300
	qminKeepLabels := 2
	anyQueryEnabled := false
	anyQueryPriority := 400
	anyQueryAction := "minimal"
	dns64HookEnabled := false
	dns64HookPriority := 500
	dns64HookPrefix := "64:ff9b::/96"
	ecsHookEnabled := false
	ecsHookPriority := 600
	ecsHookPrefixV4 := 24
	ecsHookPrefixV6 := 56
	dnssecEnabled := false
	dnssecPriority := 700
	dnssecValidation := "opportunistic"
	dnssecTrustAnchor := ""

	name := "default"
	addr := "8.8.8.8:53"
	defPriority := 0
	timeout := 5
	tcpOnly := false
	healthCheck := true
	healthInterval := 30
	healthTimeout := 5
	maxFails := 3
	weight := 1
	adaptiveFactor := 0.0

	fc := FileConfig{
		Mode:         &mode,
		DNSPort:      &dnsPort,
		UpstreamAddr: &upstream,
		Upstreams: []FileUpstreamConfig{{
			Name:                  &name,
			Address:               &addr,
			Priority:              &defPriority,
			Timeout:               &timeout,
			TCPOnly:               &tcpOnly,
			HealthCheck:           &healthCheck,
			HealthInterval:        &healthInterval,
			HealthTimeout:         &healthTimeout,
			MaxFails:              &maxFails,
			Weight:                &weight,
			AdaptiveTimeoutFactor: &adaptiveFactor,
		}},
		UpstreamConcurrency: &upstreamConcurrency,
		CacheAddr:           &cacheAddr,
		CacheFile:           &cacheFile,
		Ipv4Disable:         &ipv4Disable,
		Ipv6Disable:         &ipv6Disable,
		TcpDisable:          &tcpDisable,
		DoTEnabled:          &dotEnabled,
		DoTPort:             &dotPort,
		DoHEnabled:          &dohEnabled,
		DoHPort:             &dohPort,
		DoQEnabled:          &doqEnabled,
		DoQPort:             &doqPort,
		Dns64Prefix:         &dns64Prefix,
		EcsPrefixV4:         &ecsPrefixV4,
		EcsPrefixV6:         &ecsPrefixV6,
		TLS: &FileTLSConfig{
			CertFile:       &certFile,
			KeyFile:        &keyFile,
			CAFile:         &caFile,
			MinVersion:     &tlsMinVer,
			AutoSelfSigned: &autoSelfSigned,
		},
		RateLimit:            &rateLimit,
		StaleAge:             &staleAge,
		NegativeTTL:          &negativeTTL,
		CacheWarmup:          &cacheWarmup,
		CacheMaxEntries:      &cacheMaxEntries,
		TTLMin:               &ttlMin,
		TTLMax:               &ttlMax,
		UpstreamPoolSize:     &upstreamPoolSize,
		UpstreamPoolIdle:     &upstreamPoolIdle,
		LogLevel:             &logLevel,
		LogMode:              &logMode,
		LogDir:               &logDir,
		LogRetention:         &logRetention,
		TimeZone:             &timeZone,
		MaxTCPConnsPerClient: &maxTCPConnsPerClient,
		MetricsEnable:        &metricsEnable,
		MetricsPort:          &metricsPort,
		APIEnable:            &apiEnable,
		APIPort:              &apiPort,
		APIKey:               &apiKey,
		Hooks: &FileHookConfig{
			RateLimiting: FileRateLimitHookConfig{
				Enabled:  &hookEnabled,
				Priority: &hookPriority,
				Rate:     &hookRate,
				Action:   &hookAction,
			},
			Blocking: &FileBlockingHookConfig{
				Enabled:      &blockingEnabled,
				Priority:     &blockingPriority,
				BlockAction:  &blockingAction,
				SinkholeAddr: &blockingSinkhole,
				DomainRPS:    &blockingDomainRPS,
			},
			QMinimizer: &FileQMinimizerHookConfig{
				Enabled:    &qminEnabled,
				Priority:   &qminPriority,
				KeepLabels: &qminKeepLabels,
			},
			AnyQuery: &FileAnyQueryHookConfig{
				Enabled:  &anyQueryEnabled,
				Priority: &anyQueryPriority,
				Action:   &anyQueryAction,
			},
			Dns64: &FileDns64HookConfig{
				Enabled:  &dns64HookEnabled,
				Priority: &dns64HookPriority,
				Prefix:   &dns64HookPrefix,
			},
			ECS: &FileEcsHookConfig{
				Enabled:  &ecsHookEnabled,
				Priority: &ecsHookPriority,
				PrefixV4: &ecsHookPrefixV4,
				PrefixV6: &ecsHookPrefixV6,
			},
			Dnssec: &FileDnssecHookConfig{
				Enabled:     &dnssecEnabled,
				Priority:    &dnssecPriority,
				Validation:  &dnssecValidation,
				TrustAnchor: &dnssecTrustAnchor,
			},
		},
	}

	return writeFile(path, &fc)
}
