package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type FileUpstreamConfigTOML struct {
	Name                  *string  `toml:"name"`
	Address               *string  `toml:"address"`
	Priority              *int     `toml:"priority"`
	Timeout               *int     `toml:"timeout"`
	TCPOnly               *bool    `toml:"tcp_only"`
	TLS                   *bool    `toml:"tls"`
	TLSServerName         *string  `toml:"tls_server_name"`
	DoHURL                *string  `toml:"doh_url"`
	DoQ                   *bool    `toml:"doq"`
	HTTPProxyAddress      *string  `toml:"http_proxy_address,omitempty"`
	HTTPProxyAuth         *string  `toml:"http_proxy_auth,omitempty"`
	HTTP2Enabled          *bool    `toml:"http2_enabled,omitempty"`
	MaxIdleConnsPerHost   *int     `toml:"max_idle_conns_per_host,omitempty"`
	HealthCheck           *bool    `toml:"health_check"`
	HealthInterval        *int     `toml:"health_interval"`
	HealthTimeout         *int     `toml:"health_timeout"`
	MaxFails              *int     `toml:"max_fails"`
	Weight                *int     `toml:"weight"`
	AdaptiveTimeoutFactor *float64 `toml:"adaptive_timeout_factor"`
}

type FileConditionalRouteConfigTOML struct {
	Domain   *string `toml:"domain"`
	Upstream *string `toml:"upstream"`
}

type FileForwardingZoneConfigTOML struct {
	Domain    *string  `toml:"domain"`
	Upstreams []string `toml:"upstreams"`
	Mode      *string  `toml:"mode,omitempty"`
}

type FileTLSConfigTOML struct {
	CertFile       *string `toml:"cert_file"`
	KeyFile        *string `toml:"key_file"`
	CAFile         *string `toml:"ca_file"`
	MinVersion     *string `toml:"min_version"`
	AutoSelfSigned *bool   `toml:"auto_self_signed"`
}

type FileRateLimitHookConfigTOML struct {
	Enabled  *bool   `toml:"enabled"`
	Priority *int    `toml:"priority"`
	Rate     *int    `toml:"rate"`
	Action   *string `toml:"action"`
}

type FileTokenBucketHookConfigTOML struct {
	Enabled  *bool   `toml:"enabled"`
	Priority *int    `toml:"priority"`
	Rate     *int    `toml:"rate"`
	Burst    *int    `toml:"burst"`
	Action   *string `toml:"action"`
	Mode     *string `toml:"mode"`
}

type FileResponseRateLimitHookConfigTOML struct {
	Enabled  *bool   `toml:"enabled"`
	Priority *int    `toml:"priority"`
	Rate     *int    `toml:"rate"`
	Slip     *int    `toml:"slip"`
	Action   *string `toml:"action"`
}

type FileBlockingHookConfigTOML struct {
	Enabled         *bool    `toml:"enabled"`
	Priority        *int     `toml:"priority"`
	BlockAction     *string  `toml:"block_action"`
	SinkholeAddr    *string  `toml:"sinkhole_addr"`
	Blocklists      []string `toml:"blocklists"`
	Allowlists      []string `toml:"allowlists"`
	DomainRPS       *int     `toml:"domain_rps"`
	StatsEnabled    *bool    `toml:"stats_enabled"`
	StatsMaxDomains *int     `toml:"stats_max_domains"`
	StatsMaxClients *int     `toml:"stats_max_clients"`
	StatsRetention  *int     `toml:"stats_retention"`
}

type FileQMinimizerHookConfigTOML struct {
	Enabled    *bool `toml:"enabled"`
	Priority   *int  `toml:"priority"`
	KeepLabels *int  `toml:"keep_labels"`
}

type FileAnyQueryHookConfigTOML struct {
	Enabled  *bool   `toml:"enabled"`
	Priority *int    `toml:"priority"`
	Action   *string `toml:"action"`
}

type FileDns64HookConfigTOML struct {
	Enabled  *bool   `toml:"enabled"`
	Priority *int    `toml:"priority"`
	Prefix   *string `toml:"prefix"`
}

type FileEcsHookConfigTOML struct {
	Enabled  *bool `toml:"enabled"`
	Priority *int  `toml:"priority"`
	PrefixV4 *int  `toml:"prefix_v4"`
	PrefixV6 *int  `toml:"prefix_v6"`
}

type FileDnssecHookConfigTOML struct {
	Enabled     *bool   `toml:"enabled"`
	Priority    *int    `toml:"priority"`
	Validation  *string `toml:"validation"`
	TrustAnchor *string `toml:"trust_anchor"`
}

type FileQueryLogHookConfigTOML struct {
	Enabled       *bool   `toml:"enabled"`
	Priority      *int    `toml:"priority"`
	File          *string `toml:"file"`
	RetentionDays *int    `toml:"retention_days"`
}

type FileSpecialDomainHookConfigTOML struct {
	Enabled  *bool `toml:"enabled"`
	Priority *int  `toml:"priority"`
}

type FileHookConfigTOML struct {
	RateLimiting         *FileRateLimitHookConfigTOML         `toml:"rate_limiting"`
	TokenBucket          *FileTokenBucketHookConfigTOML       `toml:"token_bucket"`
	ResponseRateLimiting *FileResponseRateLimitHookConfigTOML `toml:"response_rate_limiting"`
	Blocking             *FileBlockingHookConfigTOML          `toml:"blocking"`
	QMinimizer           *FileQMinimizerHookConfigTOML        `toml:"qminimizer"`
	AnyQuery             *FileAnyQueryHookConfigTOML          `toml:"any_query"`
	Dns64                *FileDns64HookConfigTOML             `toml:"dns64"`
	ECS                  *FileEcsHookConfigTOML               `toml:"ecs"`
	Dnssec               *FileDnssecHookConfigTOML            `toml:"dnssec"`
	QueryLog             *FileQueryLogHookConfigTOML          `toml:"query_log"`
	SpecialDomain        *FileSpecialDomainHookConfigTOML     `toml:"special_domain"`
}

type FileTracingConfigTOML struct {
	Enable      *bool    `toml:"enable"`
	Endpoint    *string  `toml:"endpoint"`
	ServiceName *string  `toml:"service_name"`
	SampleRate  *float64 `toml:"sample_rate"`
}

type FileDHCPConfigTOML struct {
	Enabled      *bool   `toml:"enabled"`
	LeaseFile    *string `toml:"lease_file"`
	Format       *string `toml:"format,omitempty"`
	Domain       *string `toml:"domain,omitempty"`
	TTL          *int    `toml:"ttl,omitempty"`
	PollInterval *int    `toml:"poll_interval,omitempty"`
}

type FileEDNSConfigTOML struct {
	PaddingBlockSize *int `toml:"padding_block_size"`
}

type FileZoneRecordConfigTOML struct {
	Name string  `toml:"name"`
	Type string  `toml:"type"`
	TTL  *uint32 `toml:"ttl,omitempty"`

	IP         *string `toml:"ip,omitempty"`
	Target     *string `toml:"target,omitempty"`
	Preference *uint16 `toml:"preference,omitempty"`
	Host       *string `toml:"host,omitempty"`

	MName   *string `toml:"mname,omitempty"`
	RName   *string `toml:"rname,omitempty"`
	Serial  *uint32 `toml:"serial,omitempty"`
	Refresh *uint32 `toml:"refresh,omitempty"`
	Retry   *uint32 `toml:"retry,omitempty"`
	Expire  *uint32 `toml:"expire,omitempty"`
	Minimum *uint32 `toml:"minimum,omitempty"`

	SRVPriority *uint16 `toml:"srv_priority,omitempty"`
	SRVWeight   *uint16 `toml:"srv_weight,omitempty"`
	SRVPort     *uint16 `toml:"srv_port,omitempty"`
	SRVTarget   *string `toml:"srv_target,omitempty"`

	TXTData *string `toml:"txt_data,omitempty"`

	DNSKEYFlags     *uint16 `toml:"dnskey_flags,omitempty"`
	DNSKEYAlgorithm *uint8  `toml:"dnskey_algorithm,omitempty"`
	DNSKEYPublicKey *string `toml:"dnskey_public_key,omitempty"`

	RRSIGTypeCovered *uint16 `toml:"rrsig_type_covered,omitempty"`
	RRSIGAlgorithm   *uint8  `toml:"rrsig_algorithm,omitempty"`
	RRSIGLabels      *uint8  `toml:"rrsig_labels,omitempty"`
	RRSIGOriginalTTL *uint32 `toml:"rrsig_original_ttl,omitempty"`
	RRSIGExpiration  *uint32 `toml:"rrsig_expiration,omitempty"`
	RRSIGInception   *uint32 `toml:"rrsig_inception,omitempty"`
	RRSIGKeyTag      *uint16 `toml:"rrsig_key_tag,omitempty"`
	RRSIGSignerName  *string `toml:"rrsig_signer_name,omitempty"`
	RRSIGSignature   *string `toml:"rrsig_signature,omitempty"`

	NSECNextDomain *string   `toml:"nsec_next_domain,omitempty"`
	NSECTypes      *[]uint16 `toml:"nsec_types,omitempty"`
}

type FileZoneNSEC3ConfigTOML struct {
	Enabled    *bool   `toml:"enabled"`
	Iterations *uint16 `toml:"iterations,omitempty"`
	Salt       *string `toml:"salt,omitempty"`
	OptOut     *bool   `toml:"opt_out,omitempty"`
}

type FileZoneDNSSECConfigTOML struct {
	Enabled   *bool                    `toml:"enabled"`
	Algorithm *string                  `toml:"algorithm"`
	KeyFile   *string                  `toml:"key_file,omitempty"`
	ZSKFile   *string                  `toml:"zsk_file,omitempty"`
	NSEC3     *FileZoneNSEC3ConfigTOML `toml:"nsec3,omitempty"`
}

type FileZoneViewConfigTOML struct {
	Name    *string                    `toml:"name"`
	Subnet  *string                    `toml:"subnet"`
	Records []FileZoneRecordConfigTOML `toml:"records,omitempty"`
}

type FileZoneRolloverConfigTOML struct {
	Enabled    *bool `toml:"enabled"`
	ZSKDays    *int  `toml:"zsk_days,omitempty"`
	KSKDays    *int  `toml:"ksk_days,omitempty"`
	Overlap    *int  `toml:"overlap_days,omitempty"`
	PrePublish *int  `toml:"pre_publish_days,omitempty"`
}

type FileZoneConfigTOML struct {
	Name     *string                     `toml:"name"`
	Records  []FileZoneRecordConfigTOML  `toml:"records,omitempty"`
	DNSSEC   *FileZoneDNSSECConfigTOML   `toml:"dnssec,omitempty"`
	Rollover *FileZoneRolloverConfigTOML `toml:"rollover,omitempty"`
	Views    []FileZoneViewConfigTOML    `toml:"views,omitempty"`
}

type FileACLConfigTOML struct {
	Name     *string `toml:"name"`
	Action   *string `toml:"action"`
	Subnet   *string `toml:"subnet,omitempty"`
	Zone     *string `toml:"zone,omitempty"`
	Protocol *string `toml:"protocol,omitempty"`
	Upstream *string `toml:"upstream,omitempty"`
}

type FileConfigTOML struct {
	Mode                 *string                          `toml:"mode"`
	NodeName             *string                          `toml:"node_name"`
	NodeID               *string                          `toml:"node_id"`
	DNSPort              *int                             `toml:"dns_port"`
	UpstreamAddr         *string                          `toml:"upstream"`
	Upstreams            []FileUpstreamConfigTOML         `toml:"upstreams"`
	ConditionalRoutes    []FileConditionalRouteConfigTOML `toml:"conditional_routes"`
	ForwardingZones      []FileForwardingZoneConfigTOML   `toml:"forwarding_zones,omitempty"`
	UpstreamConcurrency  *int                             `toml:"upstream_concurrency"`
	CacheAddr            *string                          `toml:"cache_addr"`
	CacheFile            *string                          `toml:"cache_file"`
	Ipv4Disable          *bool                            `toml:"ipv4_disable"`
	Ipv6Disable          *bool                            `toml:"ipv6_disable"`
	TcpDisable           *bool                            `toml:"tcp_disable"`
	RateLimit            *int                             `toml:"rate_limit"`
	StaleAge             *int                             `toml:"stale_age"`
	NegativeTTL          *int                             `toml:"negative_ttl"`
	NegativeTTLMin       *int                             `toml:"negative_ttl_min"`
	CacheWarmup          *bool                            `toml:"cache_warmup"`
	CachePersistPath     *string                          `toml:"cache_persist_path"`
	PrefetchEnable       *bool                            `toml:"prefetch_enable"`
	PrefetchThreshold    *int                             `toml:"prefetch_threshold"`
	PrefetchWindow       *int                             `toml:"prefetch_window"`
	PrefetchInterval     *int                             `toml:"prefetch_interval"`
	CacheMaxEntries      *int                             `toml:"cache_max_entries"`
	TTLMin               *int                             `toml:"ttl_min"`
	TTLMax               *int                             `toml:"ttl_max"`
	UpstreamPoolSize     *int                             `toml:"upstream_pool_size"`
	UpstreamPoolIdle     *int                             `toml:"upstream_pool_idle"`
	LogLevel             *string                          `toml:"log_level"`
	LogMode              *string                          `toml:"log_mode"`
	LogDir               *string                          `toml:"log_dir"`
	LogRetention         *int                             `toml:"log_retention"`
	TimeZone             *string                          `toml:"timezone"`
	MaxTCPConnsPerClient *int                             `toml:"max_tcp_conns_per_client"`
	DebugEnable          *bool                            `toml:"debug_enable"`
	MetricsEnable        *bool                            `toml:"metrics_enable"`
	MetricsPort          *int                             `toml:"metrics_port"`
	APIEnable            *bool                            `toml:"api_enable"`
	APIPort              *int                             `toml:"api_port"`
	APIKey               *string                          `toml:"api_key"`
	DoTEnabled           *bool                            `toml:"dot_enabled"`
	DoTPort              *int                             `toml:"dot_port"`
	DoHEnabled           *bool                            `toml:"doh_enabled"`
	DoHPort              *int                             `toml:"doh_port"`
	DoQEnabled           *bool                            `toml:"doq_enabled"`
	DoQPort              *int                             `toml:"doq_port"`
	Dns64Prefix          *string                          `toml:"dns64_prefix"`
	EcsPrefixV4          *int                             `toml:"ecs_prefix_v4"`
	EcsPrefixV6          *int                             `toml:"ecs_prefix_v6"`
	TLS                  *FileTLSConfigTOML               `toml:"tls"`
	Zones                []FileZoneConfigTOML             `toml:"zones,omitempty"`
	ReusePort            *bool                            `toml:"reuse_port"`
	ReusePortWorkers     *int                             `toml:"reuse_port_workers"`
	RateLimitFailClose   *bool                            `toml:"rate_limit_fail_close"`
	ACLs                 []FileACLConfigTOML              `toml:"acls,omitempty"`
	DHCP                 *FileDHCPConfigTOML              `toml:"dhcp,omitempty"`
	Tracing              *FileTracingConfigTOML           `toml:"tracing"`
	Hooks                *FileHookConfigTOML              `toml:"hooks"`
	EDNS                 *FileEDNSConfigTOML              `toml:"edns,omitempty"`
}

func loadFileTOML(path string) (*FileConfigTOML, error) {
	var fc FileConfigTOML
	if _, err := toml.DecodeFile(path, &fc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &fc, nil
}

func loadFileTOMLBytes(data []byte) (*FileConfigTOML, error) {
	var fc FileConfigTOML
	if err := toml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse toml: %w", err)
	}
	return &fc, nil
}

func tomlUpstreamToConfigTOML(src FileUpstreamConfigTOML) UpstreamConfig {
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
	if src.HTTPProxyAddress != nil {
		dst.HTTPProxyAddress = *src.HTTPProxyAddress
	}
	if src.HTTPProxyAuth != nil {
		dst.HTTPProxyAuth = *src.HTTPProxyAuth
	}
	if src.HTTP2Enabled != nil {
		val := *src.HTTP2Enabled
		dst.HTTP2Enabled = &val
	}
	if src.MaxIdleConnsPerHost != nil {
		dst.MaxIdleConnsPerHost = *src.MaxIdleConnsPerHost
	}
	return dst
}

func tomlForwardingZoneToConfigTOML(src FileForwardingZoneConfigTOML) ForwardingZoneConfig {
	dst := ForwardingZoneConfig{
		Upstreams: src.Upstreams,
	}
	if src.Domain != nil {
		dst.Domain = *src.Domain
	}
	if src.Mode != nil {
		dst.Mode = *src.Mode
	}
	return dst
}

func tomlACLToConfigTOML(fa FileACLConfigTOML) ACLConfig {
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

func tomlZoneRecordToConfigTOML(fr FileZoneRecordConfigTOML) ZoneRecordConfig {
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

func tomlConfigToFileConfig(fcTOML *FileConfigTOML) *FileConfig {
	fc := &FileConfig{
		Mode:         fcTOML.Mode,
		NodeName:     fcTOML.NodeName,
		NodeID:       fcTOML.NodeID,
		DNSPort:      fcTOML.DNSPort,
		UpstreamAddr: fcTOML.UpstreamAddr,
	}

	for _, u := range fcTOML.Upstreams {
		fc.Upstreams = append(fc.Upstreams, FileUpstreamConfig{
			Name:                  u.Name,
			Address:               u.Address,
			Priority:              u.Priority,
			Timeout:               u.Timeout,
			TCPOnly:               u.TCPOnly,
			TLS:                   u.TLS,
			TLSServerName:         u.TLSServerName,
			DoHURL:                u.DoHURL,
			DoQ:                   u.DoQ,
			HTTPProxyAddress:      u.HTTPProxyAddress,
			HTTPProxyAuth:         u.HTTPProxyAuth,
			HTTP2Enabled:          u.HTTP2Enabled,
			MaxIdleConnsPerHost:   u.MaxIdleConnsPerHost,
			HealthCheck:           u.HealthCheck,
			HealthInterval:        u.HealthInterval,
			HealthTimeout:         u.HealthTimeout,
			MaxFails:              u.MaxFails,
			Weight:                u.Weight,
			AdaptiveTimeoutFactor: u.AdaptiveTimeoutFactor,
		})
	}

	for _, cr := range fcTOML.ConditionalRoutes {
		fc.ConditionalRoutes = append(fc.ConditionalRoutes, FileConditionalRouteConfig{
			Domain:   cr.Domain,
			Upstream: cr.Upstream,
		})
	}

	for _, fz := range fcTOML.ForwardingZones {
		fc.ForwardingZones = append(fc.ForwardingZones, FileForwardingZoneConfig{
			Domain:    fz.Domain,
			Upstreams: fz.Upstreams,
			Mode:      fz.Mode,
		})
	}

	fc.CacheAddr = fcTOML.CacheAddr
	fc.CacheFile = fcTOML.CacheFile
	fc.Ipv4Disable = fcTOML.Ipv4Disable
	fc.Ipv6Disable = fcTOML.Ipv6Disable
	fc.TcpDisable = fcTOML.TcpDisable
	fc.RateLimit = fcTOML.RateLimit
	fc.StaleAge = fcTOML.StaleAge
	fc.NegativeTTL = fcTOML.NegativeTTL
	fc.NegativeTTLMin = fcTOML.NegativeTTLMin
	fc.CacheWarmup = fcTOML.CacheWarmup
	fc.CachePersistPath = fcTOML.CachePersistPath
	fc.PrefetchEnable = fcTOML.PrefetchEnable
	fc.PrefetchThreshold = fcTOML.PrefetchThreshold
	fc.PrefetchWindow = fcTOML.PrefetchWindow
	fc.PrefetchInterval = fcTOML.PrefetchInterval
	fc.CacheMaxEntries = fcTOML.CacheMaxEntries
	fc.TTLMin = fcTOML.TTLMin
	fc.TTLMax = fcTOML.TTLMax
	fc.UpstreamPoolSize = fcTOML.UpstreamPoolSize
	fc.UpstreamPoolIdle = fcTOML.UpstreamPoolIdle
	fc.UpstreamConcurrency = fcTOML.UpstreamConcurrency
	fc.LogLevel = fcTOML.LogLevel
	fc.LogMode = fcTOML.LogMode
	fc.LogDir = fcTOML.LogDir
	fc.LogRetention = fcTOML.LogRetention
	fc.TimeZone = fcTOML.TimeZone
	fc.MaxTCPConnsPerClient = fcTOML.MaxTCPConnsPerClient
	fc.DebugEnable = fcTOML.DebugEnable
	fc.MetricsEnable = fcTOML.MetricsEnable
	fc.MetricsPort = fcTOML.MetricsPort
	fc.APIEnable = fcTOML.APIEnable
	fc.APIPort = fcTOML.APIPort
	fc.APIKey = fcTOML.APIKey
	fc.DoTEnabled = fcTOML.DoTEnabled
	fc.DoTPort = fcTOML.DoTPort
	fc.DoHEnabled = fcTOML.DoHEnabled
	fc.DoHPort = fcTOML.DoHPort
	fc.DoQEnabled = fcTOML.DoQEnabled
	fc.DoQPort = fcTOML.DoQPort
	fc.Dns64Prefix = fcTOML.Dns64Prefix
	fc.EcsPrefixV4 = fcTOML.EcsPrefixV4
	fc.EcsPrefixV6 = fcTOML.EcsPrefixV6
	fc.ReusePort = fcTOML.ReusePort
	fc.ReusePortWorkers = fcTOML.ReusePortWorkers
	fc.RateLimitFailClose = fcTOML.RateLimitFailClose

	if fcTOML.TLS != nil {
		fc.TLS = &FileTLSConfig{
			CertFile:       fcTOML.TLS.CertFile,
			KeyFile:        fcTOML.TLS.KeyFile,
			CAFile:         fcTOML.TLS.CAFile,
			MinVersion:     fcTOML.TLS.MinVersion,
			AutoSelfSigned: fcTOML.TLS.AutoSelfSigned,
		}
	}
	if fcTOML.Tracing != nil {
		fc.Tracing = &FileTracingConfig{
			Enable:      fcTOML.Tracing.Enable,
			Endpoint:    fcTOML.Tracing.Endpoint,
			ServiceName: fcTOML.Tracing.ServiceName,
			SampleRate:  fcTOML.Tracing.SampleRate,
		}
	}
	if fcTOML.DHCP != nil {
		fc.DHCP = &FileDHCPConfig{
			Enabled:      fcTOML.DHCP.Enabled,
			LeaseFile:    fcTOML.DHCP.LeaseFile,
			Format:       fcTOML.DHCP.Format,
			Domain:       fcTOML.DHCP.Domain,
			TTL:          fcTOML.DHCP.TTL,
			PollInterval: fcTOML.DHCP.PollInterval,
		}
	}
	if fcTOML.EDNS != nil {
		fc.EDNS = &FileEDNSConfig{
			PaddingBlockSize: fcTOML.EDNS.PaddingBlockSize,
		}
	}

	if fcTOML.Hooks != nil {
		h := &FileHookConfig{}
		if fcTOML.Hooks.RateLimiting != nil {
			h.RateLimiting = FileRateLimitHookConfig{
				Enabled:  fcTOML.Hooks.RateLimiting.Enabled,
				Priority: fcTOML.Hooks.RateLimiting.Priority,
				Rate:     fcTOML.Hooks.RateLimiting.Rate,
				Action:   fcTOML.Hooks.RateLimiting.Action,
			}
		}
		if fcTOML.Hooks.TokenBucket != nil {
			h.TokenBucket = &FileTokenBucketHookConfig{
				Enabled:  fcTOML.Hooks.TokenBucket.Enabled,
				Priority: fcTOML.Hooks.TokenBucket.Priority,
				Rate:     fcTOML.Hooks.TokenBucket.Rate,
				Burst:    fcTOML.Hooks.TokenBucket.Burst,
				Action:   fcTOML.Hooks.TokenBucket.Action,
				Mode:     fcTOML.Hooks.TokenBucket.Mode,
			}
		}
		if fcTOML.Hooks.ResponseRateLimiting != nil {
			h.ResponseRateLimiting = &FileResponseRateLimitHookConfig{
				Enabled:  fcTOML.Hooks.ResponseRateLimiting.Enabled,
				Priority: fcTOML.Hooks.ResponseRateLimiting.Priority,
				Rate:     fcTOML.Hooks.ResponseRateLimiting.Rate,
				Slip:     fcTOML.Hooks.ResponseRateLimiting.Slip,
				Action:   fcTOML.Hooks.ResponseRateLimiting.Action,
			}
		}
		if fcTOML.Hooks.Blocking != nil {
			h.Blocking = &FileBlockingHookConfig{
				Enabled:         fcTOML.Hooks.Blocking.Enabled,
				Priority:        fcTOML.Hooks.Blocking.Priority,
				BlockAction:     fcTOML.Hooks.Blocking.BlockAction,
				SinkholeAddr:    fcTOML.Hooks.Blocking.SinkholeAddr,
				Blocklists:      fcTOML.Hooks.Blocking.Blocklists,
				Allowlists:      fcTOML.Hooks.Blocking.Allowlists,
				DomainRPS:       fcTOML.Hooks.Blocking.DomainRPS,
				StatsEnabled:    fcTOML.Hooks.Blocking.StatsEnabled,
				StatsMaxDomains: fcTOML.Hooks.Blocking.StatsMaxDomains,
				StatsMaxClients: fcTOML.Hooks.Blocking.StatsMaxClients,
				StatsRetention:  fcTOML.Hooks.Blocking.StatsRetention,
			}
		}
		if fcTOML.Hooks.QMinimizer != nil {
			h.QMinimizer = &FileQMinimizerHookConfig{
				Enabled:    fcTOML.Hooks.QMinimizer.Enabled,
				Priority:   fcTOML.Hooks.QMinimizer.Priority,
				KeepLabels: fcTOML.Hooks.QMinimizer.KeepLabels,
			}
		}
		if fcTOML.Hooks.AnyQuery != nil {
			h.AnyQuery = &FileAnyQueryHookConfig{
				Enabled:  fcTOML.Hooks.AnyQuery.Enabled,
				Priority: fcTOML.Hooks.AnyQuery.Priority,
				Action:   fcTOML.Hooks.AnyQuery.Action,
			}
		}
		if fcTOML.Hooks.Dns64 != nil {
			h.Dns64 = &FileDns64HookConfig{
				Enabled:  fcTOML.Hooks.Dns64.Enabled,
				Priority: fcTOML.Hooks.Dns64.Priority,
				Prefix:   fcTOML.Hooks.Dns64.Prefix,
			}
		}
		if fcTOML.Hooks.ECS != nil {
			h.ECS = &FileEcsHookConfig{
				Enabled:  fcTOML.Hooks.ECS.Enabled,
				Priority: fcTOML.Hooks.ECS.Priority,
				PrefixV4: fcTOML.Hooks.ECS.PrefixV4,
				PrefixV6: fcTOML.Hooks.ECS.PrefixV6,
			}
		}
		if fcTOML.Hooks.Dnssec != nil {
			h.Dnssec = &FileDnssecHookConfig{
				Enabled:     fcTOML.Hooks.Dnssec.Enabled,
				Priority:    fcTOML.Hooks.Dnssec.Priority,
				Validation:  fcTOML.Hooks.Dnssec.Validation,
				TrustAnchor: fcTOML.Hooks.Dnssec.TrustAnchor,
			}
		}
		if fcTOML.Hooks.QueryLog != nil {
			h.QueryLog = &FileQueryLogHookConfig{
				Enabled:       fcTOML.Hooks.QueryLog.Enabled,
				Priority:      fcTOML.Hooks.QueryLog.Priority,
				File:          fcTOML.Hooks.QueryLog.File,
				RetentionDays: fcTOML.Hooks.QueryLog.RetentionDays,
			}
		}
		if fcTOML.Hooks.SpecialDomain != nil {
			h.SpecialDomain = &FileSpecialDomainHookConfig{
				Enabled:  fcTOML.Hooks.SpecialDomain.Enabled,
				Priority: fcTOML.Hooks.SpecialDomain.Priority,
			}
		}
		fc.Hooks = h
	}

	for _, z := range fcTOML.Zones {
		fz := FileZoneConfig{
			Name: z.Name,
		}
		if z.Records != nil {
			for _, r := range z.Records {
				fz.Records = append(fz.Records, FileZoneRecordConfig{
					Name:             r.Name,
					Type:             r.Type,
					TTL:              r.TTL,
					IP:               r.IP,
					Target:           r.Target,
					Preference:       r.Preference,
					Host:             r.Host,
					MName:            r.MName,
					RName:            r.RName,
					Serial:           r.Serial,
					Refresh:          r.Refresh,
					Retry:            r.Retry,
					Expire:           r.Expire,
					Minimum:          r.Minimum,
					SRVPriority:      r.SRVPriority,
					SRVWeight:        r.SRVWeight,
					SRVPort:          r.SRVPort,
					SRVTarget:        r.SRVTarget,
					TXTData:          r.TXTData,
					DNSKEYFlags:      r.DNSKEYFlags,
					DNSKEYAlgorithm:  r.DNSKEYAlgorithm,
					DNSKEYPublicKey:  r.DNSKEYPublicKey,
					RRSIGTypeCovered: r.RRSIGTypeCovered,
					RRSIGAlgorithm:   r.RRSIGAlgorithm,
					RRSIGLabels:      r.RRSIGLabels,
					RRSIGOriginalTTL: r.RRSIGOriginalTTL,
					RRSIGExpiration:  r.RRSIGExpiration,
					RRSIGInception:   r.RRSIGInception,
					RRSIGKeyTag:      r.RRSIGKeyTag,
					RRSIGSignerName:  r.RRSIGSignerName,
					RRSIGSignature:   r.RRSIGSignature,
					NSECNextDomain:   r.NSECNextDomain,
					NSECTypes:        r.NSECTypes,
				})
			}
		}
		if z.DNSSEC != nil {
			fz.DNSSEC = &FileZoneDNSSECConfig{
				Enabled:   z.DNSSEC.Enabled,
				Algorithm: z.DNSSEC.Algorithm,
				KeyFile:   z.DNSSEC.KeyFile,
				ZSKFile:   z.DNSSEC.ZSKFile,
			}
			if z.DNSSEC.NSEC3 != nil {
				fz.DNSSEC.NSEC3 = &FileZoneNSEC3Config{
					Enabled:    z.DNSSEC.NSEC3.Enabled,
					Iterations: z.DNSSEC.NSEC3.Iterations,
					Salt:       z.DNSSEC.NSEC3.Salt,
					OptOut:     z.DNSSEC.NSEC3.OptOut,
				}
			}
		}
		if z.Rollover != nil {
			fz.Rollover = &FileZoneRolloverConfig{
				Enabled:    z.Rollover.Enabled,
				ZSKDays:    z.Rollover.ZSKDays,
				KSKDays:    z.Rollover.KSKDays,
				Overlap:    z.Rollover.Overlap,
				PrePublish: z.Rollover.PrePublish,
			}
		}
		if len(z.Views) > 0 {
			for _, v := range z.Views {
				fv := FileZoneViewConfig{Name: v.Name, Subnet: v.Subnet}
				if len(v.Records) > 0 {
					for _, r := range v.Records {
						fv.Records = append(fv.Records, FileZoneRecordConfig{
							Name: r.Name, Type: r.Type, TTL: r.TTL,
							IP: r.IP, Target: r.Target,
						})
					}
				}
				fz.Views = append(fz.Views, fv)
			}
		}
		fc.Zones = append(fc.Zones, fz)
	}

	for _, a := range fcTOML.ACLs {
		fc.ACLs = append(fc.ACLs, FileACLConfig{
			Name:     a.Name,
			Action:   a.Action,
			Subnet:   a.Subnet,
			Zone:     a.Zone,
			Protocol: a.Protocol,
			Upstream: a.Upstream,
		})
	}

	return fc
}

func writeFileTOML(path string, fc *FileConfigTOML) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	header := `# northstar configuration
#
# Environment variables override every value in this file.
# Hierarchy (highest to lowest):
#   1. NORTHSTAR_* environment variables
#   2. Values in this file
#   3. Built-in defaults
#
# To use this file: place it at ./northstar.toml or set
# the NORTHSTAR_CONFIG env var to a custom path.
# If no config file exists, this file is auto-generated on startup.
# You only need to uncomment and change the values you want to override.

`
	if _, err := f.WriteString(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	enc := toml.NewEncoder(f)
	enc.Indent = ""
	if err := enc.Encode(fc); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	return nil
}

func WriteDefaultConfigTOML(path string) error {
	fc := defaultFileConfigTOML()
	return writeFileTOML(path, fc)
}

func defaultFileConfigTOML() *FileConfigTOML {
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
	negativeTTLMin := 0
	cacheWarmup := false
	cachePersistPath := ""
	prefetchEnable := false
	prefetchThreshold := 5
	prefetchWindow := 30
	prefetchInterval := 30
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
	debugEnable := false
	rateLimitFailClose := false
	tracingEnable := false
	tracingEndpoint := "localhost:4317"
	tracingServiceName := "northstar"
	tracingSampleRate := 0.1
	reusePort := true
	reusePortWorkers := 0
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
	tbEnabled := false
	tbPriority := 100
	tbRate := 0
	tbBurst := 0
	tbAction := "servfail"
	tbMode := "memory"
	rrlEnabled := false
	rrlPriority := 800
	rrlRate := 0
	rrlSlip := 2
	rrlAction := "drop"
	blockingEnabled := false
	blockingPriority := 200
	blockingAction := "nxdomain"
	blockingSinkhole := "127.0.0.1"
	blockingDomainRPS := 0
	blockingStatsEnabled := true
	blockingStatsMaxDomains := 1000
	blockingStatsMaxClients := 1000
	blockingStatsRetention := 30
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
	queryLogEnabled := false
	queryLogPriority := 900
	queryLogFile := "./query.log"
	queryLogRetention := 7
	specialDomainEnabled := true
	specialDomainPriority := 60

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

	nodeName := ""
	nodeID := ""
	ednsPadding := 0

	return &FileConfigTOML{
		Mode:         &mode,
		NodeName:     &nodeName,
		NodeID:       &nodeID,
		DNSPort:      &dnsPort,
		UpstreamAddr: &upstream,
		Upstreams: []FileUpstreamConfigTOML{{
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
		TLS: &FileTLSConfigTOML{
			CertFile:       &certFile,
			KeyFile:        &keyFile,
			CAFile:         &caFile,
			MinVersion:     &tlsMinVer,
			AutoSelfSigned: &autoSelfSigned,
		},
		RateLimit:          &rateLimit,
		StaleAge:           &staleAge,
		NegativeTTL:        &negativeTTL,
		NegativeTTLMin:     &negativeTTLMin,
		RateLimitFailClose: &rateLimitFailClose,
		Tracing: &FileTracingConfigTOML{
			Enable:      &tracingEnable,
			Endpoint:    &tracingEndpoint,
			ServiceName: &tracingServiceName,
			SampleRate:  &tracingSampleRate,
		},
		ReusePort:            &reusePort,
		ReusePortWorkers:     &reusePortWorkers,
		CacheWarmup:          &cacheWarmup,
		CachePersistPath:     &cachePersistPath,
		PrefetchEnable:       &prefetchEnable,
		PrefetchThreshold:    &prefetchThreshold,
		PrefetchWindow:       &prefetchWindow,
		PrefetchInterval:     &prefetchInterval,
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
		DebugEnable:          &debugEnable,
		MetricsEnable:        &metricsEnable,
		MetricsPort:          &metricsPort,
		APIEnable:            &apiEnable,
		APIPort:              &apiPort,
		APIKey:               &apiKey,
		EDNS: &FileEDNSConfigTOML{
			PaddingBlockSize: &ednsPadding,
		},
		Hooks: &FileHookConfigTOML{
			RateLimiting: &FileRateLimitHookConfigTOML{
				Enabled:  &hookEnabled,
				Priority: &hookPriority,
				Rate:     &hookRate,
				Action:   &hookAction,
			},
			TokenBucket: &FileTokenBucketHookConfigTOML{
				Enabled:  &tbEnabled,
				Priority: &tbPriority,
				Rate:     &tbRate,
				Burst:    &tbBurst,
				Action:   &tbAction,
				Mode:     &tbMode,
			},
			ResponseRateLimiting: &FileResponseRateLimitHookConfigTOML{
				Enabled:  &rrlEnabled,
				Priority: &rrlPriority,
				Rate:     &rrlRate,
				Slip:     &rrlSlip,
				Action:   &rrlAction,
			},
			Blocking: &FileBlockingHookConfigTOML{
				Enabled:         &blockingEnabled,
				Priority:        &blockingPriority,
				BlockAction:     &blockingAction,
				SinkholeAddr:    &blockingSinkhole,
				DomainRPS:       &blockingDomainRPS,
				StatsEnabled:    &blockingStatsEnabled,
				StatsMaxDomains: &blockingStatsMaxDomains,
				StatsMaxClients: &blockingStatsMaxClients,
				StatsRetention:  &blockingStatsRetention,
			},
			QMinimizer: &FileQMinimizerHookConfigTOML{
				Enabled:    &qminEnabled,
				Priority:   &qminPriority,
				KeepLabels: &qminKeepLabels,
			},
			AnyQuery: &FileAnyQueryHookConfigTOML{
				Enabled:  &anyQueryEnabled,
				Priority: &anyQueryPriority,
				Action:   &anyQueryAction,
			},
			Dns64: &FileDns64HookConfigTOML{
				Enabled:  &dns64HookEnabled,
				Priority: &dns64HookPriority,
				Prefix:   &dns64HookPrefix,
			},
			ECS: &FileEcsHookConfigTOML{
				Enabled:  &ecsHookEnabled,
				Priority: &ecsHookPriority,
				PrefixV4: &ecsHookPrefixV4,
				PrefixV6: &ecsHookPrefixV6,
			},
			Dnssec: &FileDnssecHookConfigTOML{
				Enabled:     &dnssecEnabled,
				Priority:    &dnssecPriority,
				Validation:  &dnssecValidation,
				TrustAnchor: &dnssecTrustAnchor,
			},
			QueryLog: &FileQueryLogHookConfigTOML{
				Enabled:       &queryLogEnabled,
				Priority:      &queryLogPriority,
				File:          &queryLogFile,
				RetentionDays: &queryLogRetention,
			},
			SpecialDomain: &FileSpecialDomainHookConfigTOML{
				Enabled:  &specialDomainEnabled,
				Priority: &specialDomainPriority,
			},
		},
	}
}
