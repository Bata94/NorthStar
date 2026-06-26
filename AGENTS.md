# northstar — Agent Context

## Project
`github.com/bata94/northstar` — a learning DNS server in Go (1.26) that forwards queries to upstream resolvers, caches responses, serves authoritative zones, filters with blocklists/RPZ/ACLs, and responds to clients over plain DNS, DoT, DoH, and DoQ.

## Architecture

```
main.go
  └─ config.Load() → Config{Mode, NodeName, NodeID, DNSPort, UpstreamAddr, Upstreams[], ConditionalRoutes[], UpstreamConcurrency, CacheAddr, CacheFile, CacheWarmup, Listeners, Ipv4Disable, Ipv6Disable, TcpDisable, RateLimit, StaleAge, NegativeTTL, TTLMin, TTLMax, CacheMaxEntries, MaxTCPConnsPerClient, UpstreamPoolSize, UpstreamPoolIdle, LogLevel, LogMode, LogDir, LogRetention, TimeZone, TLS{CertFile,KeyFile,CAFile,MinVersion,AutoSelfSigned}, DoTEnabled, DoTPort, DoHEnabled, DoHPort, DoQEnabled, DoQPort, DebugEnable, MetricsEnable, MetricsPort, APIEnable, APIPort, APIKey, ConfigPath, Dns64Prefix, EcsPrefixV4, EcsPrefixV6, Zones[], ACLs[], ReusePort, ReusePortWorkers, RateLimitFailClose, Tracing{Enable,Endpoint,ServiceName,SampleRate}, Hooks}
  │    └─ load .env (godotenv, no-overwrite) + YAML file + env vars
  │    └─ overlay env vars on top (env > file > defaults)
  │    └─ auto-generate default file if missing (main.go pre-flight)
  └─ node.InstanceID() + node.NodeName(cfg.NodeName) → instance identity (startup log, API /status)
  └─ config.NewRuntimeConfig(&cfg) → atomic runtime values for SIGHUP reload
  └─ buildPipeline(&cfg, cache, metrics) → resolver.SetPipeline(p) (atomic swap)
  │    └─ registers hooks: SpecialDomain, Authoritative, Acl, RateLimit, Blocking (filter+RPZ), QMinimizer, AnyQuery, Dns64, Ecs, Dnssec, QueryLog
  └─ cache.NewMemory(maxEntries, m) or cache.NewValkey(addr, staleAge, m) or cache.NewBbolt(path, staleAge, m) → cache.Cache (metrics for eviction counters; TryLock/Unlock for cross-node coordination)
  └─ log.New(level, mode) → slog.Logger (consoleHandler + JSON file)
  └─ metrics.New() → *metrics.Metrics (custom prometheus registry, 18+ collectors)
  └─ if DebugEnable → /debug/pprof/ mounted on metrics HTTP server
  └─ upstream.NewGroup(cfg, m) → *Group (health checking, concurrent forwarding, conditional routing, adaptive timeouts)
  └─ resolver.NewPool(upstream, udp) + resolver.NewPool(upstream, tcp) → *Pool
  └─ if APIEnable → api.New(cfg, group, cache, metrics, hooks, zoneSet, aclSet).Serve() → REST API on port 9163
  └─ if Tracing.Enable → tracing.Init(cfg, nodeID, nodeName) → OTLP gRPC exporter, graceful shutdown
  └─ signal.NotifyContext → ctx (SIGTERM/SIGINT)
  └─ signal.Notify → sighupCh (SIGHUP → reload config + rebuild pipeline)
  └─ if MetricsEnable → metrics.Serve(ctx, addr, m) (goroutine)
  └─ resolver.Serve(ctx, Listener, upstream, cache, staleAge, pool, m, pipeline)  (× listeners)
  │    └─ if !TcpDisable → resolver.ServeTCP(ctx, Listener, upstream, cache, staleAge, pool, m, pipeline)
  │    └─ if DoTEnabled → resolver.ServeDOT(ctx, tlsCfg, port, upstream, cache, staleAge, pool, m, pipeline)
  │    └─ if DoHEnabled → resolver.ServeDOH(ctx, tlsCfg, port, upstream, cache, staleAge, pool, m, pipeline)
  │    └─ if DoQEnabled → resolver.ServeDOQ(ctx, tlsCfg, port, upstream, cache, staleAge, pool, m, pipeline)
  │
  ├─ Serve: UDP read loop (1s deadline for ctx polling)
  │    └─ go handleRequest(ctx, data, remoteAddr, conn, upstream, cache, staleAge, pool, m, pipeline)
  │         └─ processQuery(ctx, req, network, clientIP, maxPayload, do, send, upstream, cache, staleAge, pool, m, pipeline)
  │              ├─ m.QueriesTotal (by qtype)
  │              ├─ pipeline.Run(PreResolve, hookCtx) → special domain, authoritative zone, ACL, rate limit, blocking, QNAME min, ANY, DNS64, ECS
  │              │    ├─ SpecialDomainHook: localhost→loopback, invalid/test→NXDOMAIN, local→REFUSED
  │              │    ├─ AuthoritativeHook (prio 50): longest-suffix zone match, serve zone records, DNSSEC signing
  │              │    ├─ AclHook (prio 150): subnet/zone/protocol matching → allow/refuse/drop/route
  │              │    ├─ RateLimitHook: cache.Incr(key, 1s) → SERVFAIL if exceeded
  │              │    ├─ BlockingHook: blocklist/allowlist/RPZ/per-domain rate limit → nxdomain/sinkhole/refused/drop
  │              │    ├─ QMinimizerPreHook (prio 300): strip labels, store original
  │              │    ├─ AnyQueryHook (prio 400): HINFO response per RFC 8482
  │              │    ├─ Dns64Hook (prio 500): AAAA synthesis from cached A records
  │              │    └─ EcsHook (prio 600): inject EDNS0 client subnet option
  │              ├─ resolve(ctx, Name, Type, upstream, cache, maxPayload, network, staleAge, pool, do, m)
  │              │    ├─ m.CacheLookups.Inc()
  │              │    ├─ cache.Peek(ctx, domain, qtype) → fresh hit → m.CacheHits.Inc(), return
  │              │    ├─ stale-while-revalidate: if staleAge > 0 && stale.Peek → refreshCache() goroutine, return stale
  │              │    │   └─ cross-node: cache.TryLock("northstar:inflight:stale:...") → elects one refresher
  │              │    ├─ inflight dedup: inflightKey{domain,qtype} → wait or become leader (local-only)
  │              │    ├─ cross-node dedup: cache.TryLock("northstar:inflight:...") → leader fetches, losers poll Peek
  │              │    │   └─ lock key: "northstar:inflight:<domain>:<qtype>" with 10s TTL
  │              │    │   └─ poll loop: 50ms sleep × 100 iterations (5s max)
  │              │    │   └─ on poll timeout → fall through to direct fetch
  │              │    └─ fetchFromUpstream(ctx, domain, qtype, maxPayload, network, pool, do, m)
  │              │         └─ selects upstream (or preferred from ACL route), acquires conn, forwards, parses reply, releases
  │              │         └─ concurrent forwarding: raceUpstreams() queries N upstreams in parallel, return first valid
  │              ├─ pipeline.Run(PostResolve, hookCtx)
  │              │    └─ QMinimizerPostHook (prio 301): restore original name
  │              │    └─ DnssecHook (prio 700): RRSIG verification, sets AuthenticData
  │              ├─ entry.CopyRecordsWithAdjustedTTL() → build response
  │              ├─ pipeline.Run(PreResponse, hookCtx)
  │              ├─ if len(packed) > maxPayload → set TC bit, truncate
  │              ├─ send(respPacked)
  │              └─ pipeline.Run(PostResponse, hookCtx)
  │                   └─ QueryLogHook (prio 900): CSV log with daily rotation
  │
  ├─ ServeTCP: TCP accept loop (1s deadline)
  │    └─ go handleTCPConnection(ctx, conn, upstream, cache, staleAge, pool, m, pipeline)
  │         └─ processQuery(...) (same flow as UDP)
  │
  ├─ ServeDOT: TCP + TLS handshake → handleTCPConnection (same flow)
  │
  ├─ ServeDOH: HTTP server on /dns-query, POST (application/dns-message) + GET (base64url ?dns=)
  │    └─ processQuery(...) (same flow)
  │
  └─ ServeDOQ: QUIC listener (quic-go), per-stream DNS query
       └─ processQuery(...) (same flow)
```

## Packages

### `config`
- Structs: `Config` (50+ fields), `Listener`, `TLSConfig`, `UpstreamConfig`, `ConditionalRouteConfig`, `ZoneConfig`, `ACLConfig`, `TracingConfig`, `HookConfig`, `BlockingHookConfig`, `RateLimitHookConfig`, `QMinimizerHookConfig`, `AnyQueryHookConfig`, `Dns64HookConfig`, `EcsHookConfig`, `DnssecHookConfig`, `SpecialDomainHookConfig`, `QueryLogHookConfig`, `RPZConfig`
- `Load()` reads `.env` (godotenv, no-overwrite) + YAML file + env vars
- Override hierarchy: defaults < YAML file < environment variables
- Env keys: NORTHSTAR_MODE, NORTHSTAR_DNS_PORT, NORTHSTAR_UPSTREAM, NORTHSTAR_CACHE_ADDR, NORTHSTAR_CACHE_FILE, NORTHSTAR_DNS_CACHE_WARMUP, NORTHSTAR_DNS_IPV4_DISABLE, NORTHSTAR_DNS_IPV6_DISABLE, NORTHSTAR_TCP_DISABLE, NORTHSTAR_DNS_RATE_LIMIT, NORTHSTAR_DNS_STALE_AGE, NORTHSTAR_DNS_NEGATIVE_TTL, NORTHSTAR_DNS_TTL_MIN, NORTHSTAR_DNS_TTL_MAX, NORTHSTAR_DNS_CACHE_MAX_ENTRIES, NORTHSTAR_MAX_TCP_CONNS_PER_CLIENT, NORTHSTAR_UPSTREAM_POOL_SIZE, NORTHSTAR_UPSTREAM_POOL_IDLE, NORTHSTAR_UPSTREAM_CONCURRENCY, NORTHSTAR_LOG_LEVEL, NORTHSTAR_LOG_MODE, NORTHSTAR_LOG_DIR, NORTHSTAR_LOG_RETENTION, NORTHSTAR_TZ, NORTHSTAR_METRICS_ENABLE, NORTHSTAR_METRICS_PORT, NORTHSTAR_DEBUG_ENABLE, NORTHSTAR_TLS_CERT_FILE, NORTHSTAR_TLS_KEY_FILE, NORTHSTAR_TLS_CA_FILE, NORTHSTAR_TLS_AUTO_SELF_SIGNED, NORTHSTAR_DOT_ENABLED, NORTHSTAR_DOT_PORT, NORTHSTAR_DOH_ENABLED, NORTHSTAR_DOH_PORT, NORTHSTAR_DOQ_ENABLED, NORTHSTAR_DOQ_PORT, NORTHSTAR_DNS64_PREFIX, NORTHSTAR_ECS_PREFIX_V4, NORTHSTAR_ECS_PREFIX_V6, NORTHSTAR_API_ENABLE, NORTHSTAR_API_PORT, NORTHSTAR_API_KEY, NORTHSTAR_REUSE_PORT, NORTHSTAR_REUSE_PORT_WORKERS, NORTHSTAR_RATE_LIMIT_FAIL_CLOSE, NORTHSTAR_NODE_NAME, NORTHSTAR_NODE_ID, NORTHSTAR_TRACING_ENABLE, NORTHSTAR_TRACING_ENDPOINT, NORTHSTAR_TRACING_SAMPLE_RATE, NORTHSTAR_CONFIG
- `CacheAddr` defaults to `""` (in-memory); set to Valkey address for external cache
- `CacheFile` enables bbolt file-based cache (Low RAM Mode)
- If both v4+v6 enabled → single `::` listener (dual-stack bind)
- If one disabled → separate listeners for the enabled family
- `ConfigPath` — path to YAML file (env `NORTHSTAR_CONFIG`, default `./northstar.yaml`)
- `Load()` auto-generates default YAML file if missing (done in main.go pre-flight)
- `Reload()` — re-reads config file + env vars for SIGHUP hot-reload
- `RuntimeConfig` — atomic values for hot-swappable settings (RateLimit, StaleAge, LogLevel, LogMode)
- `WriteDefaultConfig(path)` — writes a complete YAML file with all defaults and hierarchy explanation header

### `dns`
- Wire-format types: `Header`, `Question`, `ResourceRecord`, `Message`
- `Message.Parse(data)` — decodes with compression, fresh `visited` map per name read
- `Message.Pack()` — encodes with name compression via suffix map
- `ResourceRecord.A()` / `AAAA()` — typed accessors
- `readName` / `writeName` — unexported label helpers
- `BuildECSOption(clientIP, prefixLen)` — EDNS0 option for ECS
- DNSSEC: RRSIG validation helpers (RSASHA256, RSASHA512, ECDSAP256, ECDSAP384, Ed25519)

### `cache`
- `Cache` interface: `Get(ctx, domain, qtype)`, `Peek(ctx, domain, qtype)`, `Set(ctx, entry)`, `Incr(ctx, key, ttl)`, `Delete(ctx, domain, qtype)`, `DeleteDomain(ctx, domain)`, `Len()`, `Evictions()`, `Warmup(ctx, dest Cache)`, `TryLock(ctx, key, ttl)`, `Unlock(ctx, key)`, `Flush(ctx)`, `Close()`
- Three backends: `Memory` (in-memory, `sync.RWMutex`-protected), `Valkey` (Valkey/Redis-compatible, via `valkey-go`), `Bbolt` (file-based, via `go.etcd.io/bbolt`)
- Keyed by `(domain, qtype)` — each query type cached independently
- `NewEntry(domain, qtype, answers, auth, addl, rcode, negativeTTL, ttlMin, ttlMax)` — computes expiry from min TTL or SOA minimum; negative entries have separate TTL
- `Entry.Expired()` — `time.Now().After(ExpiresAt)`
- `Entry.CopyRecordsWithAdjustedTTL()` — deep copies with remaining TTL (floors at 1s)
- `Entry.RCode` — reflects upstream response RCODE
- `Entry.AuthenticData` — AD bit from upstream
- `Entry.Flags` — full upstream header flags
- `Entry.HitCount` / `RecordHit()` — access pattern tracking for LRU eviction
- `Entry.lastHitAt` — timestamp of last access
- Valkey backend: raw `dns.Message.Pack()` wire bytes as value, native key TTL, `valkey.IsValkeyNil` for cache misses
- Bbolt backend: binary value format with version byte, expiration timestamp, hit count
- `Memory` has LRU eviction (container/list + map) with max entry limit
- Eviction goroutine (5min ticker) removes expired entries and expired rate-limit counters
- Cache warming: `Bbolt.Warmup()` iterates entries and pushes to destination cache

### `log`
- Custom `consoleHandler` — colored output in dev mode (DBG=cyan, INF=green, WRN=yellow, ERR=red), plain in prod
- `multiHandler` — writes to both console (colored) and `northstar.log` (JSON)
- `New(levelStr, mode)` — creates `slog.Logger`; level from config (`NORTHSTAR_LOG_LEVEL`), log-to-`northstar.log` file always tried

### Log Level Conventions
Default prod level is `warn`.
- **`Error`** — real service degradation: upstream failures, cache backend errors, drain timeouts, cache set failures, SERVFAIL returned, background refresh failures, response truncation. Also syscall/IO failures.
- **`Warn`** — lifecycle events operators should see in prod: server startup/shutdown, listener addresses, shutdown initiation, draining. Notable anomalies: rate limit exceeded, malformed client requests, Valkey operational errors, DNSSEC validation failures (opportunistic mode).
- **`Info`** — notable operational events visible only when `logLevel=info`: stale-while-revalidate behavior, response truncation, cache backend choice, query log rotation, speed assessment results.
- **`Debug`** — high-frequency per-query tracing: cache hit/miss, query completion, inflight dedup waits. Only visible in dev mode.

### `hooks`
- `Lifecycle` enum: `PreResolve`, `PostResolve`, `PreResponse`, `PostResponse`
- `Context` struct carrying request state (`Request`, `Response`, `Entry`, `ClientIP`, `Network`, `Cache`, `Metrics`, `Send`, `Ctx`, `PreferredUpstream`, `ECSData`, `Logger`)
- `Hook` interface: `Name()`, `Lifecycle()`, `Priority()`, `Enabled()`, `Handle(*Context) error`
- `ErrHookStop` — short-circuits pipeline (used by AnyQueryHook, AclHook, BlockingHook)
- `Pipeline` — thread-safe sorted slices per lifecycle; `Register()` inserts by priority, `Run()` iterates enabled hooks
- Built-in hooks (in priority order):
  - `SpecialDomainHook` (PreResolve, prio 60) — RFC 6761 handling
  - `AuthoritativeHook` (PreResolve, prio 50) — local zone serving + DNSSEC signing
  - `AclHook` (PreResolve, prio 150) — network ACL evaluation
  - `RateLimitHook` (PreResolve, prio 100) — per-client rate limit via cache.Incr
  - `BlockingHook` (PreResolve, prio 200) — blocklist/allowlist/RPZ/per-domain rate limit
  - `QMinimizerPreHook` (PreResolve, prio 300) — QNAME minimization
  - `AnyQueryHook` (PreResolve, prio 400) — RFC 8482 ANY handling
  - `Dns64Hook` (PreResolve, prio 500) — AAAA synthesis from cached A records
  - `EcsHook` (PreResolve, prio 600) — EDNS client subnet injection
  - `QMinimizerPostHook` (PostResolve, prio 301) — restore original name
  - `DnssecHook` (PostResolve, prio 700) — RRSIG verification
  - `QueryLogHook` (PostResponse, prio 900) — CSV query log with daily rotation
- Phase 1–13: all hooks wired; config enables/disables each individually

### `lock`
- Distributed mutex backed by Valkey (`SET NX EX` for TryLock, Lua script for safe Unlock)
- `NewMutex(client, key, ttl)` — generates random owner ID
- `InProcessMutex` — in-process sync.Mutex fallback for non-Valkey backends

### `node`
- `InstanceID()` — random UUID generated once per process via `crypto/rand`
- `NodeName(cfgName)` — configurable name, falls back to `os.Hostname()`

### `resolver`
- No globals except `inflightCalls` map and `pipelinePtr` atomic (package-level, shared across listeners)
- `SetPipeline(p)` — atomically swaps the hook pipeline; called at startup and on SIGHUP reload
- `processQuery` loads the current pipeline via `pipelinePtr.Load()` on each request
- `Serve` (UDP) / `ServeTCP` — accept loops with 1s deadline for ctx polling, graceful drain (5s timeout)
- `ServeDOT(ctx, tlsCfg, addr, ...)` — TCP + TLS, delegates to handleTCPConnection
- `ServeDOH(ctx, tlsCfg, addr, ...)` — HTTP server on /dns-query, POST + GET methods
- `ServeDOQ(ctx, tlsCfg, addr, ...)` — QUIC listener via quic-go, per-stream query
- SO_REUSEPORT: `listenConfig(reusePort bool)` returns `net.ListenConfig` with `Control` func setting SO_REUSEPORT socket option
- Multiple workers: when `ReusePortWorkers > 1`, main.go spawns N goroutines per listener with independent sockets
- `inflightKey{domain, qtype}` / `inflightCall{done, entry, err, once}` — dedup concurrent queries
- `refreshCache()` — background goroutine for stale-while-revalidate
- `fetchFromUpstream()` — acquires connection from pool, forwards query (UDP/TCP/TLS/DoH/DoQ), parses reply, releases connection; measures latency
- Concurrent forwarding: when multiple upstreams configured, queries N in parallel and returns first valid response
- Upstream selection: respects `PreferredUpstream` from ACL route, health status, priority, EWMA latency
- `clientEDNS()` — parses OPT record for client payload size and DO bit
- `stripOPT()` — removes OPT record before caching
- On upstream error → SERVFAIL (RCODE 2), never caches failures
- Response truncation (TC bit) when packed message exceeds `maxPayload`
- Workers spawned via `go handleRequest(...)` / `go handleTCPConnection(...)`
- TCP/DoT reads: `SetReadDeadline(10s)`, goroutine closes conn on `ctx.Done()`
- TCP/DoT writes: `SetWriteDeadline(10s)` in `writeTCPResponse()`
- Upstream writes: `SetWriteDeadline(10s)`, goroutine closes conn on `ctx.Done()`
- Failed inflight calls → removed from map, fall through to direct upstream fetch
- Cross-node dedup: Valkey-based TryLock before upstream fetch; losers poll Peek() with 50ms interval

### `resolver/pool`
- `Pool` struct — `[]idleConn` slice, `sync.Mutex`, max idle count, idle timeout
- `Acquire(ctx)` — pops from idle or `DialContext` (supports plain UDP/TCP)
- `Release(conn, err)` — returns to pool on nil err, closes on error or if pool full/closed
- `sweeper()` — goroutine ticks at `idleTO / 2`, evicts stale idle connections
- Two pool instances created in `main.go` (UDP and TCP)

### `upstream`
- `Upstream` struct — `Name`, `Config`, `UDPPool`, `TCPPool`, `DoH`/`DoQ` client, `healthy` atomic, `failCount`, `ewmaLatency`
- `Group` struct — upstream list sorted by priority/latency, `byName` map, conditional routes, concurrency limit, health checker
- `Group.SelectN(ctx, domain, n)` — returns N healthiest upstreams for a domain (considering conditional routes)
- `Group.GetByName(name)` — for ACL route lookups
- `HealthChecker` — periodic probes (jittered interval), tracks fail count, demotes/promotes upstreams
- Speed assessment: 5-minute ticker logs EWMA latency rankings
- Adaptive timeouts: `Upstream.AdaptiveTimeout()` = max(static, EWMA * factor)
- `DoHClient` — HTTP POST to DoH URL with application/dns-message content type
- `DoQClient` — QUIC-based DNS query via quic-go
- Upstream config: `address`, `priority`, `timeout`, `tcp_only`, `tls`, `tls_server_name`, `doh_url`, `doq`, `health_check`, `health_interval`, `health_timeout`, `max_fails`, `weight`, `adaptive_timeout_factor`

### `filter`
- `Filter` struct — `blocklist *List` + `allowlist *List` with wildcard/glob support
- `List` — `[]rule` with raw string + isWildcard bool
- `RPZSet` — Response Policy Zones, each with `*List` + `Action`
- `Match(domain)` — checks allowlist first (takes precedence), then blocklist
- `MatchRPZ(domain)` — checks RPZ entries
- Parser supports: bare domain, `*.example.com`, `||example.com^` (AdGuard), `0.0.0.0 example.com` (Pi-hole), comments (`#`/`!`)
- Hot-reload via `LoadFiles()` / `LoadRPZFiles()` — atomically swaps rule sets

### `zone`
- `Zone` struct — `Name`, `Records []Record`, `DNSSEC *DNSSECConfig`, `SigningKey crypto.Signer`, `byName map`
- `Set` struct — sorted zones by name length desc (longest suffix first)
- `Record` interface: `DNSName()`, `DNSType()`, `TTL()`, `RData()` (wire format)
- Concrete record types: `ARecord`, `AAAARecord`, `CNAMERecord`, `NSRecord`, `MXRecord`, `SOARecord`, `TXTRecord`, `SRVRecord`, `DNSKEYRecord`, `RRSIGRecord`, `NSECRecord`
- `ParseConfig(zoneName string, cfg ZoneConfig)` — builds Zone from YAML config
- `FindBest(name)` — longest-suffix zone match
- `BuildResponse(zone, name, qtype)` — builds DNS response with NXDOMAIN/NODATA as appropriate
- `AttachDNSSEC(msg, zone, name, qtype)` — attaches RRSIG, NSEC, DNSKEY records
- DNSSEC signing: ECDSA P-256/P-384 key loading/generation, RRSIG generation, NSEC chain building
- `GenerateKey(algorithm)` — auto-generates signing key with 10-year validity

### `acl`
- `Rule` struct — `Name`, `Action` (allow/refuse/drop/route), `Subnet *net.IPNet`, `Zone`, `Protocol`, `Upstream`
- `RuleSet` struct — sorted rules for sequential matching
- `Match(clientIP, zone, protocol)` — returns first matching rule or nil
- All fields optional — empty field = match any

### `api`
- `Server` struct — wraps config, upstream group, cache, metrics, blocking hook, authoritative hook, ACL hook
- `envelope` — JSON response envelope `{ok, data, error}`
- Auth via `X-API-Key` header or `?api_key=` query param (health endpoint unauthenticated)
- REST API at `/api/v1/*` on configurable port (default 9163)
- Full CRUD for upstreams, zones, ACLs; cache inspection/management; filter status/reload; system health/status/config

### `tls`
- `ServerConfig(cfg)` — creates `*tls.Config` for DoT/DoH/DoQ server listeners
- `ClientConfig(cfg, serverName)` — creates `*tls.Config` for upstream TLS connections
- `ensureSelfSigned(certFile, keyFile)` — auto-generates ECDSA P-256 self-signed cert (1 year validity, SAN: localhost, northstar.local, 127.0.0.1, ::1)

### `tracing`
- `Config` struct — `Enable`, `Endpoint`, `ServiceName`, `SampleRate`, `InstanceID`, `NodeName`
- `Init(cfg)` — creates OTLP gRPC exporter, batch span processor, tracer provider
- `SetTracer(t)` — registers tracer for use across packages
- 4 span types: `dns.query`, `dns.resolve`, `dns.upstream_query`, `dns.hook.<name>`
- Resource attributes: `service.name`, `service.instance.id`, `node.name`
- Sampler: ParentBased(TraceIDRatioBased, sampleRate)
- Graceful shutdown with 5s timeout
- Noop tracer fallback when disabled or on init error

### `metrics`
- `Metrics` struct with 18+ collectors + custom `prometheus.Registry`
  - `QueriesTotal` — CounterVec by `qtype`
  - `CacheLookups` / `CacheHits` — Counter
  - `CacheEvictionsTotal` — CounterVec by `backend` (memory/valkey/bbolt)
  - `NegativeCacheLookups` / `NegativeCacheHits` — Counter
  - `UpstreamLatency` — HistogramVec by `name` (buckets: 1ms–5s)
  - `UpstreamProbeDuration` — HistogramVec by `name`
  - `UpstreamQueries` / `UpstreamFails` — CounterVec by `name`
  - `UpstreamConditionalHits` — CounterVec by `name`, `pattern`
  - `UpstreamHealthy` — GaugeVec by `name`
  - `ErrorsTotal` — CounterVec by `type` (parse_error, rate_limited, servfail)
  - `ActiveHandlers` — Gauge
  - `BlockedTotal` — CounterVec by `action`, `qtype`
  - `DnssecValidationStatus` — CounterVec by `status`
  - `Dns64SynthesesTotal` — Counter
  - `EcsQueriesTotal` — CounterVec by `family`
  - `ZoneQueriesTotal` — CounterVec by `zone`, `qtype`
- `New()` — creates registry and registers all collectors
- `Handler()` — `promhttp.HandlerFor(m.Registry, ...)`
- `Serve(ctx, addr, m)` — HTTP server on address, `/metrics` handler, graceful shutdown

## Dependencies
- `github.com/joho/godotenv` — `.env` loading
- `github.com/valkey-io/valkey-go` — Valkey/Redis-compatible cache backend
- `github.com/prometheus/client_golang/prometheus` — Prometheus metrics
- `github.com/prometheus/client_golang/prometheus/promhttp` — HTTP handler for metrics
- `go.etcd.io/bbolt` — file-based cache backend (Low RAM Mode)
- `github.com/quic-go/quic-go` — DNS-over-QUIC transport
- `go.opentelemetry.io/otel` — OpenTelemetry tracing SDK + OTLP gRPC exporter

## Tests
- 15+ test files across 12+ packages
- `internal/testutil/` — shared helpers: MockUpstream (UDP/TCP), DNS builders, metrics/config/group factories, SendUDPQuery
- `resolver/testdata/domains.go` — 1000+ curated domains (popular, niche, IDN, edge, diverse TLDs)
- `resolver/output_test.go` — integration test comparing northstar vs 9.9.9.9/8.8.8.8/1.1.1.1 (build tag `integration`)
- `resolver/blast_test.go` — blast tests: concurrent throughput, cache stress, inflight dedup stress
- `resolver/bench_test.go` — benchmarks: resolve cache hit/miss/NXDOMAIN, parse message, pack message, concurrent resolve
- Cross-node integration tests (docker-compose.test.yml) — 2 northstar instances + 1 Valkey; 7 tests for lock, stampede, stale-revalidate, rate-limit, cache flush, coordination, DNS query
- RFC correctness tests — EDNS version negotiation, truncation, unknown RR types, special-use domains, negative caching, class handling, name compression
- Fuzz tests — 3 fuzz functions (parse message, compression pointers, write/read name), 380k+ execs
- Recipes:
  - `just test` — basic tests (no race, no cover)
  - `just test-fast` — `go test -count=1 -race -shuffle=on ./...`
  - `just test-cover` — `go test -coverprofile=coverage.out -covermode=atomic ./...`
  - `just test-all` — `go test -count=1 -race -shuffle=on -tags=integration -coverprofile=...`
  - `just test-blast` — blast + benchmark tests only
  - `just bench` — all benchmarks

After big changes and before commits, run `just check` to run all tests and linters.

## Usage (Docker-only)

The server runs exclusively inside Docker containers.

### Production (distroless)
```shell
docker compose up northstar
```

### Development (hot-reload with air)
```shell
docker compose up northstar-dev
```
### Lint
```shell
just lint
```

## New Features

After big changes and before commits, run `just check` to run all tests and linters.
Add new features to `README.md`.

### Git

For commits use commonly used conventions and prefix commit messages with `feat:`, `fix:`, `docs:`, `style:`, `refactor:`, `test:`, or `chore:`.

## Build
- `Dockerfile` — multi-stage, `gcr.io/distroless/static-debian12:nonroot`, ~5 MB, non-root (uid 65532)
- `Dockerfile.dev` — `golang:1.26-alpine` + `github.com/air-verse/air` hot reload
- `CGO_ENABLED=0 go build -ldflags="-s -w"` (inside Dockerfile; local builds optional)

## Docker
- `docker-compose.yml` — three services (`northstar`, `northstar-dev`, `valkey`), `cap_add: NET_BIND_SERVICE` for ports <1024
- Valkey service: `valkey/valkey:8-alpine`, ephemeral (no volume), `restart: unless-stopped`
- Default port 8053 (override via `NORTHSTAR_DNS_PORT`)
- Resource limits: 2 CPUs, 2048M memory per service
- `.env` + `environment:` compose block for configuration
- `docker-compose.test.yml` — 2 northstar instances + 1 Valkey for cross-node integration tests
- Multi-node same-host: set `NORTHSTAR_REUSE_PORT=true`, shared `NORTHSTAR_CACHE_ADDR=valkey:6379`, distinct ports for metrics/API
- Cross-node dedup: uses `cache.TryLock` via Valkey; each node's `inflightCalls` map adds fast local dedup on top

## License
- MIT + Commons Clause v1.0 — see `LICENSE`
- Permits personal, home, and non-profit use
- Prohibits selling the software itself (i.e., distributing or offering it as a service without adding significant value)
