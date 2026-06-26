// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Listener struct {
	IP        string
	Port      int
	ReusePort bool
}

func ResolveConfigPath() (path string, isTOML bool) {
	path = "./northstar.yaml"
	if v, ok := os.LookupEnv("NORTHSTAR_CONFIG"); ok && v != "" {
		path = v
	}
	isTOML = strings.HasSuffix(path, ".toml") || strings.HasSuffix(path, ".TOML")
	return
}

func loadAnyFile(path string) (*FileConfig, error) {
	if strings.HasSuffix(path, ".toml") || strings.HasSuffix(path, ".TOML") {
		fcTOML, err := loadFileTOML(path)
		if err != nil {
			return nil, err
		}
		return tomlConfigToFileConfig(fcTOML), nil
	}
	return loadFile(path)
}

func loadAnyFileWithFallback(path string, isTOML bool) *FileConfig {
	if fc, err := loadAnyFile(path); err == nil {
		return fc
	}
	if !isTOML {
		if fc, err := loadFile("./northstar.toml"); err == nil {
			return fc
		}
	}
	return nil
}

type RateLimitHookConfig struct {
	Enabled  bool
	Priority int
	Rate     int
	Action   string
}

type TokenBucketHookConfig struct {
	Enabled  bool
	Priority int
	Rate     int    // tokens per second
	Burst    int    // max token accumulation; 0 = same as Rate
	Action   string // "servfail" or "drop"
	Mode     string // "memory" (default) or "valkey"
}

type ResponseRateLimitHookConfig struct {
	Enabled  bool
	Priority int    // default 800 (runs after DNSSEC, before send)
	Rate     int    // responses per second per client/RCODE
	Slip     int    // every Nth response is sent (default 2, 0 = never drop)
	Action   string // "drop" (default) or "truncate"
}

type RPZConfig struct {
	Path   string
	Action string // nxdomain, sinkhole, passthru, drop
}

type BlocklistURLConfig struct {
	URL             string
	RefreshInterval int // minutes, default 1440 (24h)
}

type BlockingHookConfig struct {
	Enabled         bool
	Priority        int
	BlockAction     string   // nxdomain, sinkhole, refused, drop
	SinkholeAddr    string   // default "127.0.0.1"
	Blocklists      []string // file paths
	Allowlists      []string // file paths
	BlocklistURLs   []BlocklistURLConfig
	DomainRPS       int // per-domain rate limit (0 = disabled)
	RPZ             []RPZConfig
	StatsEnabled    bool // default true
	StatsMaxDomains int  // default 1000
	StatsMaxClients int  // default 1000
	StatsRetention  int  // days, default 30
}

type HookConfig struct {
	RateLimiting         RateLimitHookConfig
	TokenBucket          TokenBucketHookConfig
	ResponseRateLimiting ResponseRateLimitHookConfig
	Blocking             BlockingHookConfig
	QMinimizer           QMinimizerHookConfig
	AnyQuery             AnyQueryHookConfig
	Dns64                Dns64HookConfig
	ECS                  EcsHookConfig
	Dnssec               DnssecHookConfig
	QueryLog             QueryLogHookConfig
	SpecialDomain        SpecialDomainHookConfig
}

type UpstreamConfig struct {
	Name                  string
	Address               string
	Priority              int
	Timeout               int // seconds, default 5
	TCPOnly               bool
	TLS                   bool    // DNS-over-TLS
	TLSServerName         string  // SNI override for DoT/DoH/DoQ
	DoHURL                string  // DNS-over-HTTPS URL (e.g., "https://example.com/dns-query")
	DoQ                   bool    // DNS-over-QUIC
	HTTPProxyAddress      string  // HTTP CONNECT proxy URL (e.g., "http://proxy.corp:3128")
	HTTPProxyAuth         string  // Basic auth "user:pass" for proxy (optional)
	HTTP2Enabled          *bool   // nil = enabled for DoH (default true)
	MaxIdleConnsPerHost   int     // max idle connections per DoH host (default 10)
	HealthCheck           bool    // default true
	HealthInterval        int     // seconds, default 30
	HealthTimeout         int     // seconds, default 5
	MaxFails              int     // default 3
	Weight                int     // default 1
	AdaptiveTimeoutFactor float64 // multiplier for EWMA latency; 0 = disabled
}

type ConditionalRouteConfig struct {
	Domain   string
	Upstream string
}

type ForwardingZoneConfig struct {
	Domain    string
	Upstreams []string
	Mode      string // "forward-only" or "forward-first"
}

type QMinimizerHookConfig struct {
	Enabled    bool
	Priority   int
	KeepLabels int
}

type AnyQueryHookConfig struct {
	Enabled  bool
	Priority int
	Action   string // "minimal" or "forward"
}

type Dns64HookConfig struct {
	Enabled  bool
	Priority int
	Prefix   string // NAT64 prefix, default "64:ff9b::/96"
}

type EcsHookConfig struct {
	Enabled  bool
	Priority int
	PrefixV4 int // source prefix length for IPv4 (default 24)
	PrefixV6 int // source prefix length for IPv6 (default 56)
}

type ZoneRolloverConfig struct {
	Enabled    bool // enable automatic key rollover
	ZSKDays    int  // ZSK lifetime in days (default 30)
	KSKDays    int  // KSK lifetime in days (default 365)
	Overlap    int  // overlap period in days for double-signature (default 7)
	PrePublish int  // pre-publish period in days for ZSK (default 2)
}

type DnssecHookConfig struct {
	Enabled     bool
	Priority    int
	Validation  string // "required" or "opportunistic"
	TrustAnchor string // path to root trust anchor file
}

type QueryLogHookConfig struct {
	Enabled       bool
	Priority      int
	File          string // query log file path, default "./query.log"
	RetentionDays int    // log retention in days, default 7
}

type SpecialDomainHookConfig struct {
	Enabled  bool
	Priority int
}

type ZoneRecordConfig struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
	TTL  uint32 `yaml:"ttl"`

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

type ZoneNSEC3Config struct {
	Enabled    bool   `yaml:"enabled"`
	Iterations uint16 `yaml:"iterations,omitempty"`
	Salt       string `yaml:"salt,omitempty"` // hex-encoded; empty = auto-generate
	OptOut     bool   `yaml:"opt_out,omitempty"`
}

type ZoneDNSSECConfig struct {
	Enabled   bool             `yaml:"enabled"`
	Algorithm string           `yaml:"algorithm"`
	KeyFile   string           `yaml:"key_file,omitempty"`
	ZSKFile   string           `yaml:"zsk_file,omitempty"`
	NSEC3     *ZoneNSEC3Config `yaml:"nsec3,omitempty"`
}

type ZoneViewConfig struct {
	Name    string             `yaml:"name"`
	Subnet  string             `yaml:"subnet"` // CIDR match for client IP
	Records []ZoneRecordConfig `yaml:"records"`
}

type ZoneConfig struct {
	Name     string              `yaml:"name"`
	Records  []ZoneRecordConfig  `yaml:"records"`
	DNSSEC   *ZoneDNSSECConfig   `yaml:"dnssec,omitempty"`
	Rollover *ZoneRolloverConfig `yaml:"rollover,omitempty"`
	Views    []ZoneViewConfig    `yaml:"views,omitempty"`
}

type ACLConfig struct {
	Name     string `yaml:"name"`
	Action   string `yaml:"action"`
	Subnet   string `yaml:"subnet,omitempty"`
	Zone     string `yaml:"zone,omitempty"`
	Protocol string `yaml:"protocol,omitempty"`
	Upstream string `yaml:"upstream,omitempty"`
}

type TLSConfig struct {
	CertFile       string
	KeyFile        string
	CAFile         string
	MinVersion     string // "1.2" or "1.3"
	AutoSelfSigned bool
}

type TracingConfig struct {
	Enable      bool
	Endpoint    string  // OTLP gRPC endpoint, default "localhost:4317"
	ServiceName string  // default "northstar"
	SampleRate  float64 // 0.0-1.0, default 0.1
}

type DHCPConfig struct {
	Enabled      bool
	LeaseFile    string
	Format       string // "dnsmasq" (default) or "isc"
	Domain       string // domain suffix for DHCP hostnames
	TTL          uint32 // default 300
	PollInterval int    // seconds, default 30
}

type Config struct {
	Mode                 string
	NodeName             string
	NodeID               string
	DNSPort              int
	UpstreamAddr         string // deprecated, use Upstreams
	Upstreams            []UpstreamConfig
	ConditionalRoutes    []ConditionalRouteConfig
	UpstreamConcurrency  int // number of upstreams to query in parallel (0/1 = disabled)
	CacheAddr            string
	CacheFile            string
	Listeners            []Listener
	Ipv4Disable          bool
	Ipv6Disable          bool
	TcpDisable           bool
	RateLimit            int
	StaleAge             int
	NegativeTTL          int
	NegativeTTLMin       int
	TTLMin               int
	TTLMax               int
	CacheMaxEntries      int
	UpstreamPoolSize     int
	UpstreamPoolIdle     int
	LogLevel             string
	LogMode              string
	LogDir               string
	LogRetention         int
	TimeZone             string
	TLS                  TLSConfig
	DoTEnabled           bool
	DoTPort              int
	DoHEnabled           bool
	DoHPort              int
	DoQEnabled           bool
	DoQPort              int
	CacheWarmup          bool
	CachePersistPath     string // path to persist in-memory cache on shutdown
	PrefetchEnable       bool
	PrefetchThreshold    int // minimum hit count for prefetch, default 5
	PrefetchWindow       int // seconds before expiry to prefetch, default 30
	PrefetchInterval     int // seconds between scan cycles, default 30
	MaxTCPConnsPerClient int
	DebugEnable          bool
	MetricsEnable        bool
	MetricsPort          int
	APIEnable            bool
	APIPort              int
	APIKey               string
	ConfigPath           string
	Dns64Prefix          string // NAT64 prefix, default "64:ff9b::/96"
	EcsPrefixV4          int    // source prefix length for IPv4 (default 24)
	EcsPrefixV6          int    // source prefix length for IPv6 (default 56)
	ForwardingZones      []ForwardingZoneConfig
	Zones                []ZoneConfig
	ACLs                 []ACLConfig
	EDNSPaddingBlockSize int // EDNS padding block size; 0 = disabled, 128/256 typical
	ReusePort            bool
	ReusePortWorkers     int
	RateLimitFailClose   bool
	DHCP                 DHCPConfig
	Tracing              TracingConfig
	Hooks                HookConfig
}

func Load() Config {
	loadDotEnv()

	cfgPath, _ := ResolveConfigPath()

	cfg := Config{
		ConfigPath:   cfgPath,
		Mode:         "prod",
		NodeName:     "",
		NodeID:       "",
		DNSPort:      53,
		UpstreamAddr: "8.8.8.8:53",
		CacheAddr:    "",
		CacheFile:    "",
		Ipv4Disable:  false,
		Ipv6Disable:  false,
		TcpDisable:   false,
		TLS: TLSConfig{
			MinVersion:     "1.2",
			AutoSelfSigned: true,
		},
		DoTEnabled:           true,
		DoTPort:              853,
		DoHEnabled:           true,
		DoHPort:              443,
		DoQEnabled:           true,
		DoQPort:              853,
		RateLimit:            0,
		StaleAge:             60,
		NegativeTTL:          0,
		NegativeTTLMin:       0,
		TTLMin:               0,
		TTLMax:               0,
		CacheMaxEntries:      0,
		UpstreamPoolSize:     10,
		UpstreamPoolIdle:     30,
		LogLevel:             "",
		LogMode:              "",
		LogDir:               ".",
		LogRetention:         7,
		TimeZone:             "",
		CacheWarmup:          false,
		CachePersistPath:     "",
		PrefetchEnable:       false,
		PrefetchThreshold:    5,
		PrefetchWindow:       30,
		PrefetchInterval:     30,
		MaxTCPConnsPerClient: 0,
		DebugEnable:          false,
		MetricsEnable:        false,
		MetricsPort:          9153,
		APIEnable:            false,
		APIPort:              9163,
		APIKey:               "",
		Dns64Prefix:          "64:ff9b::/96",
		EcsPrefixV4:          24,
		EcsPrefixV6:          56,
		EDNSPaddingBlockSize: 0,
		ReusePort:            true,
		ReusePortWorkers:     0,
		RateLimitFailClose:   false,
		DHCP: DHCPConfig{
			Enabled:      false,
			LeaseFile:    "",
			Format:       "dnsmasq",
			Domain:       "lan",
			TTL:          300,
			PollInterval: 30,
		},
		Tracing: TracingConfig{
			Enable:      false,
			Endpoint:    "localhost:4317",
			ServiceName: "northstar",
			SampleRate:  0.1,
		},
		Zones: nil,
		ACLs:  nil,
		Hooks: HookConfig{
			RateLimiting: RateLimitHookConfig{
				Enabled:  false,
				Priority: 100,
				Rate:     0,
				Action:   "servfail",
			},
			TokenBucket: TokenBucketHookConfig{
				Enabled:  false,
				Priority: 100,
				Rate:     0,
				Burst:    0,
				Action:   "servfail",
				Mode:     "memory",
			},
			ResponseRateLimiting: ResponseRateLimitHookConfig{
				Enabled:  false,
				Priority: 800,
				Rate:     0,
				Slip:     2,
				Action:   "drop",
			},
			Blocking: BlockingHookConfig{
				Enabled:         false,
				Priority:        200,
				BlockAction:     "nxdomain",
				SinkholeAddr:    "127.0.0.1",
				DomainRPS:       0,
				StatsEnabled:    true,
				StatsMaxDomains: 1000,
				StatsMaxClients: 1000,
				StatsRetention:  30,
			},
			QMinimizer: QMinimizerHookConfig{
				Enabled:    false,
				Priority:   300,
				KeepLabels: 2,
			},
			AnyQuery: AnyQueryHookConfig{
				Enabled:  false,
				Priority: 400,
				Action:   "minimal",
			},
			Dns64: Dns64HookConfig{
				Enabled:  false,
				Priority: 500,
				Prefix:   "64:ff9b::/96",
			},
			ECS: EcsHookConfig{
				Enabled:  false,
				Priority: 600,
				PrefixV4: 24,
				PrefixV6: 56,
			},
			Dnssec: DnssecHookConfig{
				Enabled:     false,
				Priority:    700,
				Validation:  "opportunistic",
				TrustAnchor: "",
			},
			QueryLog: QueryLogHookConfig{
				Enabled:       false,
				Priority:      900,
				File:          "./query.log",
				RetentionDays: 7,
			},
			SpecialDomain: SpecialDomainHookConfig{
				Enabled:  true,
				Priority: 60,
			},
		},
	}

	if fc := loadAnyFileWithFallback(cfgPath, false); fc != nil {
		applyFileConfig(&cfg, fc)
		applyFileZones(&cfg, fc)
		applyFileACLs(&cfg, fc)
	}

	applyEnvOverrides(&cfg)
	migrateUpstreams(&cfg)

	if cfg.Ipv4Disable && cfg.Ipv6Disable {
		panic("No IP addresses provided. Please set either NORTHSTAR_DNS_IPV4_DISABLE or NORTHSTAR_DNS_IPV6_DISABLE to false")
	}

	if cfg.UpstreamConcurrency < 1 {
		cfg.UpstreamConcurrency = 1
	}

	cfg.Listeners = buildListeners(cfg.DNSPort, cfg.Ipv4Disable, cfg.Ipv6Disable, cfg.ReusePort)

	return cfg
}

func Reload() (Config, error) {
	loadDotEnv()

	cfgPath, isTOML := ResolveConfigPath()

	cfg := Config{
		ConfigPath:   cfgPath,
		Mode:         "prod",
		NodeName:     "",
		NodeID:       "",
		DNSPort:      53,
		UpstreamAddr: "8.8.8.8:53",
		CacheAddr:    "",
		CacheFile:    "",
		Ipv4Disable:  false,
		Ipv6Disable:  false,
		TcpDisable:   false,
		TLS: TLSConfig{
			MinVersion:     "1.2",
			AutoSelfSigned: true,
		},
		DoTEnabled:           true,
		DoTPort:              853,
		DoHEnabled:           true,
		DoHPort:              443,
		DoQEnabled:           true,
		DoQPort:              853,
		RateLimit:            0,
		StaleAge:             60,
		NegativeTTL:          0,
		NegativeTTLMin:       0,
		TTLMin:               0,
		TTLMax:               0,
		CacheMaxEntries:      0,
		UpstreamPoolSize:     10,
		UpstreamPoolIdle:     30,
		UpstreamConcurrency:  1,
		LogLevel:             "",
		LogMode:              "",
		LogDir:               ".",
		LogRetention:         7,
		TimeZone:             "",
		CacheWarmup:          false,
		CachePersistPath:     "",
		PrefetchEnable:       false,
		PrefetchThreshold:    5,
		PrefetchWindow:       30,
		PrefetchInterval:     30,
		MaxTCPConnsPerClient: 0,
		MetricsEnable:        false,
		MetricsPort:          9153,
		APIEnable:            false,
		APIPort:              9163,
		APIKey:               "",
		Dns64Prefix:          "64:ff9b::/96",
		EcsPrefixV4:          24,
		EcsPrefixV6:          56,
		EDNSPaddingBlockSize: 0,
		ReusePort:            true,
		ReusePortWorkers:     0,
		RateLimitFailClose:   false,
		DHCP: DHCPConfig{
			Enabled:      false,
			LeaseFile:    "",
			Format:       "dnsmasq",
			Domain:       "lan",
			TTL:          300,
			PollInterval: 30,
		},
		Tracing: TracingConfig{
			Enable:      false,
			Endpoint:    "localhost:4317",
			ServiceName: "northstar",
			SampleRate:  0.1,
		},
		Zones: nil,
		ACLs:  nil,
		Hooks: HookConfig{
			RateLimiting: RateLimitHookConfig{
				Enabled:  false,
				Priority: 100,
				Rate:     0,
				Action:   "servfail",
			},
			TokenBucket: TokenBucketHookConfig{
				Enabled:  false,
				Priority: 100,
				Rate:     0,
				Burst:    0,
				Action:   "servfail",
				Mode:     "memory",
			},
			ResponseRateLimiting: ResponseRateLimitHookConfig{
				Enabled:  false,
				Priority: 800,
				Rate:     0,
				Slip:     2,
				Action:   "drop",
			},
			Blocking: BlockingHookConfig{
				Enabled:         false,
				Priority:        200,
				BlockAction:     "nxdomain",
				SinkholeAddr:    "127.0.0.1",
				DomainRPS:       0,
				StatsEnabled:    true,
				StatsMaxDomains: 1000,
				StatsMaxClients: 1000,
				StatsRetention:  30,
			},
			QMinimizer: QMinimizerHookConfig{
				Enabled:    false,
				Priority:   300,
				KeepLabels: 2,
			},
			AnyQuery: AnyQueryHookConfig{
				Enabled:  false,
				Priority: 400,
				Action:   "minimal",
			},
			Dns64: Dns64HookConfig{
				Enabled:  false,
				Priority: 500,
				Prefix:   "64:ff9b::/96",
			},
			ECS: EcsHookConfig{
				Enabled:  false,
				Priority: 600,
				PrefixV4: 24,
				PrefixV6: 56,
			},
			Dnssec: DnssecHookConfig{
				Enabled:     false,
				Priority:    700,
				Validation:  "opportunistic",
				TrustAnchor: "",
			},
			QueryLog: QueryLogHookConfig{
				Enabled:       false,
				Priority:      900,
				File:          "./query.log",
				RetentionDays: 7,
			},
			SpecialDomain: SpecialDomainHookConfig{
				Enabled:  true,
				Priority: 60,
			},
		},
	}

	if fc := loadAnyFileWithFallback(cfgPath, isTOML); fc != nil {
		applyFileConfig(&cfg, fc)
		applyFileZones(&cfg, fc)
		applyFileACLs(&cfg, fc)
	}

	applyEnvOverrides(&cfg)
	migrateUpstreams(&cfg)

	if cfg.Ipv4Disable && cfg.Ipv6Disable {
		return cfg, fmt.Errorf("both IPv4 and IPv6 are disabled")
	}

	if cfg.UpstreamConcurrency < 1 {
		cfg.UpstreamConcurrency = 1
	}

	cfg.Listeners = buildListeners(cfg.DNSPort, cfg.Ipv4Disable, cfg.Ipv6Disable, cfg.ReusePort)

	return cfg, nil
}

func loadDotEnv() {
	if envMap, err := godotenv.Read(); err == nil {
		for k, v := range envMap {
			if os.Getenv(k) == "" {
				if err := os.Setenv(k, v); err != nil {
					panic(fmt.Sprintf("invalid env var %s: %v", k, err))
				}
			}
		}
	}
}

func applyEnvOverrides(cfg *Config) {
	if v, ok := os.LookupEnv("NORTHSTAR_MODE"); ok {
		cfg.Mode = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_NODE_NAME"); ok {
		cfg.NodeName = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_NODE_ID"); ok {
		cfg.NodeID = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_PORT"); ok {
		cfg.DNSPort = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_UPSTREAM"); ok {
		cfg.UpstreamAddr = v
		parseUpstreamEnv(cfg, v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_CACHE_ADDR"); ok {
		cfg.CacheAddr = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_CACHE_FILE"); ok {
		cfg.CacheFile = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_IPV4_DISABLE"); ok {
		cfg.Ipv4Disable = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_IPV6_DISABLE"); ok {
		cfg.Ipv6Disable = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TCP_DISABLE"); ok {
		cfg.TcpDisable = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_RATE_LIMIT"); ok {
		cfg.RateLimit = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_STALE_AGE"); ok {
		cfg.StaleAge = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_NEGATIVE_TTL_CAP"); ok {
		cfg.NegativeTTL = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_NEGATIVE_TTL"); ok {
		cfg.NegativeTTL = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_NEGATIVE_TTL_MIN"); ok {
		cfg.NegativeTTLMin = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_CACHE_MAX_ENTRIES"); ok {
		cfg.CacheMaxEntries = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_TTL_MIN"); ok {
		cfg.TTLMin = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_TTL_MAX"); ok {
		cfg.TTLMax = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_UPSTREAM_POOL_SIZE"); ok {
		cfg.UpstreamPoolSize = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_UPSTREAM_POOL_IDLE"); ok {
		cfg.UpstreamPoolIdle = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_UPSTREAM_CONCURRENCY"); ok {
		cfg.UpstreamConcurrency = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_LOG_LEVEL"); ok {
		cfg.LogLevel = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_LOG_MODE"); ok {
		cfg.LogMode = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_LOG_DIR"); ok {
		cfg.LogDir = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_LOG_RETENTION"); ok {
		cfg.LogRetention = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TZ"); ok {
		cfg.TimeZone = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_CACHE_WARMUP"); ok {
		cfg.CacheWarmup = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_CACHE_PERSIST_PATH"); ok {
		cfg.CachePersistPath = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_CACHE_PREFETCH_ENABLE"); ok {
		cfg.PrefetchEnable = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_CACHE_PREFETCH_THRESHOLD"); ok {
		cfg.PrefetchThreshold = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_CACHE_PREFETCH_WINDOW"); ok {
		cfg.PrefetchWindow = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_CACHE_PREFETCH_INTERVAL"); ok {
		cfg.PrefetchInterval = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS_MAX_TCP_CONNS_PER_CLIENT"); ok {
		cfg.MaxTCPConnsPerClient = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_REUSE_PORT"); ok {
		cfg.ReusePort = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_REUSE_PORT_WORKERS"); ok {
		cfg.ReusePortWorkers = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TOKEN_BUCKET_RATE"); ok {
		cfg.Hooks.TokenBucket.Rate = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TOKEN_BUCKET_BURST"); ok {
		cfg.Hooks.TokenBucket.Burst = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TOKEN_BUCKET_ACTION"); ok {
		cfg.Hooks.TokenBucket.Action = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TOKEN_BUCKET_MODE"); ok {
		cfg.Hooks.TokenBucket.Mode = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_RRL_ENABLED"); ok {
		cfg.Hooks.ResponseRateLimiting.Enabled = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_RRL_RATE"); ok {
		cfg.Hooks.ResponseRateLimiting.Rate = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_RRL_SLIP"); ok {
		cfg.Hooks.ResponseRateLimiting.Slip = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_RRL_ACTION"); ok {
		cfg.Hooks.ResponseRateLimiting.Action = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_RATE_LIMIT_FAIL_CLOSE"); ok {
		cfg.RateLimitFailClose = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DEBUG_ENABLE"); ok {
		cfg.DebugEnable = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_METRICS_ENABLE"); ok {
		cfg.MetricsEnable = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_METRICS_PORT"); ok {
		cfg.MetricsPort = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TLS_CERT_FILE"); ok {
		cfg.TLS.CertFile = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TLS_KEY_FILE"); ok {
		cfg.TLS.KeyFile = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TLS_CA_FILE"); ok {
		cfg.TLS.CAFile = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TLS_MIN_VERSION"); ok {
		cfg.TLS.MinVersion = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TLS_AUTO_SELF_SIGNED"); ok {
		cfg.TLS.AutoSelfSigned = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DOT_ENABLED"); ok {
		cfg.DoTEnabled = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DOT_PORT"); ok {
		cfg.DoTPort = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DOH_ENABLED"); ok {
		cfg.DoHEnabled = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DOH_PORT"); ok {
		cfg.DoHPort = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DOQ_ENABLED"); ok {
		cfg.DoQEnabled = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DOQ_PORT"); ok {
		cfg.DoQPort = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_DNS64_PREFIX"); ok {
		cfg.Dns64Prefix = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_ECS_PREFIX_V4"); ok {
		cfg.EcsPrefixV4 = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_ECS_PREFIX_V6"); ok {
		cfg.EcsPrefixV6 = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_API_ENABLE"); ok {
		cfg.APIEnable = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_API_PORT"); ok {
		cfg.APIPort = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_API_KEY"); ok {
		cfg.APIKey = v
	}
	// ConfigPath override (not from file, directly via env)
	if v, ok := os.LookupEnv("NORTHSTAR_CONFIG"); ok {
		cfg.ConfigPath = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_EDNS_PADDING_BLOCK_SIZE"); ok {
		cfg.EDNSPaddingBlockSize = atoiOrZero(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TRACING_ENABLE"); ok {
		cfg.Tracing.Enable = isTrue(v)
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TRACING_ENDPOINT"); ok {
		cfg.Tracing.Endpoint = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TRACING_SERVICE_NAME"); ok {
		cfg.Tracing.ServiceName = v
	}
	if v, ok := os.LookupEnv("NORTHSTAR_TRACING_SAMPLE_RATE"); ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Tracing.SampleRate = f
		}
	}
}

func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func isTrue(s string) bool {
	return strings.EqualFold(s, "true")
}

func parseUpstreamEnv(cfg *Config, v string) {
	if !strings.Contains(v, "=") {
		return
	}
	var upstreams []UpstreamConfig
	for _, entry := range strings.Split(v, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		rest := strings.TrimSpace(parts[1])
		fields := strings.SplitN(rest, ",", 2)
		addr := strings.TrimSpace(fields[0])
		priority := 0
		if len(fields) > 1 {
			priority = atoiOrZero(strings.TrimSpace(fields[1]))
		}
		if name == "" || addr == "" {
			continue
		}
		upstreams = append(upstreams, UpstreamConfig{
			Name:           name,
			Address:        addr,
			Priority:       priority,
			Timeout:        5,
			HealthCheck:    true,
			HealthInterval: 30,
			HealthTimeout:  5,
			MaxFails:       3,
			Weight:         1,
		})
	}
	if len(upstreams) > 0 {
		cfg.Upstreams = upstreams
	}
}

func migrateUpstreams(cfg *Config) {
	if len(cfg.Upstreams) == 0 && cfg.UpstreamAddr != "" {
		cfg.Upstreams = []UpstreamConfig{{
			Name:           "default",
			Address:        cfg.UpstreamAddr,
			Priority:       0,
			Timeout:        5,
			HealthCheck:    true,
			HealthInterval: 30,
			HealthTimeout:  5,
			MaxFails:       3,
			Weight:         1,
		}}
	}
}

func buildListeners(port int, disableIPv4, disableIPv6 bool, reusePort bool) []Listener {
	if !disableIPv4 && !disableIPv6 {
		return []Listener{{IP: "::", Port: port, ReusePort: reusePort}}
	}
	var listeners []Listener
	if !disableIPv4 {
		listeners = append(listeners, Listener{IP: "0.0.0.0", Port: port, ReusePort: reusePort})
	}
	if !disableIPv6 {
		listeners = append(listeners, Listener{IP: "::", Port: port, ReusePort: reusePort})
	}
	return listeners
}
