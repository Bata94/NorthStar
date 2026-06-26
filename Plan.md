# northstar — Roadmap

> Comprehensive list of planned features. Prioritization TBD — this is the
> complete set before ordering by milestone.

## Transport Security & Privacy

- [X] DNS-over-HTTPS (DoH) — both upstream and client-facing listener
- [X] DNS-over-TLS (DoT) — both upstream and client-facing listener
- [X] DNS-over-QUIC (DoQ) — both upstream and client-facing listener
- [X] QNAME Minimization — strip labels from query name before forwarding
  to reduce disclosure to upstream resolvers

## Caching

- [X] Cache hit counter + last-hit timestamp — track per-entry access
  patterns for smarter eviction
- [X] Limit cache size by entry count — evict oldest + least-used entries
  when capacity is reached
- [X] Keep top entries warm / Adaptive prefetch — proactively refresh
  popular entries before they expire (configurable popularity threshold
  and prefetch window)
- [X] TTL Overwrite — global min/max TTL override to reduce upstream
  queries (e.g., floor at 30s, cap at 1h)
- [X] Negative caching (RFC 2308) — cache NXDOMAIN and NODATA responses
  with separate (typically shorter) TTLs
- [X] Cache warming on startup — reload popular entries from Valkey or
  bbolt on restart to avoid a cold-cache storm
- [X] Cache persistence to disk on shutdown — save in-memory cache
  entries to a file on graceful shutdown for warm restart
- [X] Aggressive negative TTL override — configurable floor/cap for
  negative TTL that overrides SOA minimum field

## Upstream Management

- [X] Concurrent forwarding — query multiple upstreams in parallel with
  configurable concurrency; return first valid response
- [X] Periodic speed assessment — measure upstream latency periodically
  and prefer the fastest N upstreams automatically
- [X] Upstream priorities — primary / fallback tiers with automatic
  promotion/demotion
- [X] Health checking with automatic failover — periodic health probes;
  remove unhealthy upstreams from rotation
- [X] Conditional forwarding — route by domain suffix
  (e.g., `*.internal.corp` → private resolver)
- [X] Adaptive timeouts per upstream — track historical latency and
  adjust timeouts dynamically per upstream
- [ ] HTTP CONNECT proxy support for DoH upstream — tunnel through
  an HTTP CONNECT proxy for outbound DoH queries
- [ ] HTTP/2 connection coalescing for DoH upstream — reuse a single
  HTTP/2 connection for multiple concurrent queries to the same upstream

## Blocking & Filtering

- [X] Blocklists — file-based, one domain per line, wildcard/glob support
  (`*.example.com`)
- [X] Allowlists — takes precedence over blocklists
- [X] Configurable block action — NXDOMAIN / 127.0.0.1 sinkhole / REFUSED /
  drop silently
- [X] Hot-reload blocklist/allowlist files — SIGHUP-based reload without
  restart
- [X] Response Policy Zones (RPZ) — more sophisticated blocking via
  policy zone files (compatible with common RPZ feeds)
- [X] Blocklist format compatibility — optionally consume AdGuard Home and
  Pi-hole list formats
- [X] Per-domain rate limiting — limit queries to specific domains (e.g.,
  high-cardinality subdomains used in DDoS amplification)
- [X] URL-based blocklist sources — auto-download blocklists from URLs
  with periodic refresh and caching
- [X] Ad blocking analytics / reporting — top blocked domains, top
  blocked clients, blocked-vs-allowed ratios

## Low RAM Mode

- [X] File-based cache backend (bbolt) — on-disk storage, minimal memory
  footprint
- [X] Environment variable toggle — `NORTHSTAR_CACHE_FILE` to enable;
  falls back to current memory/Valkey logic when unset
- [X] Periodic expiry compaction — bbolt auto-compaction to reclaim space

## Configuration & API

- [X] REST API — focused on serving the WebUI, but fully usable from
  external programs for programmatic control (CRUD upstreams,
  blocklists, zones, cache operations, runtime config)
- [X] YAML config file — single source of truth with env var
  override hierarchy (file < env var < API)
- [X] Hot-reload on SIGHUP — re-read config file without restart
- [ ] Configuration validation command — `northstar check-config` to
  validate the config file before starting the server
- [ ] TOML config file support — alternative to YAML with identical
  field mapping and env var override hierarchy

## Middleware & Hooks System

- [X] Plugin-like hook pipeline — pre-defined lifecycle points:
  pre-resolve, post-resolve, pre-response, post-response
- [X] Built-in hook implementations:
  - Rate limiting (replaces current hardcoded check)
  - ACL evaluation
  - Blocklist / Allowlist filtering
  - QNAME minimization
  - Query logging
- [X] Users can enable/disable and reorder hooks via config
- [ ] Lua scripting for custom logic — embed Lua hooks for arbitrary
  query manipulation at any lifecycle point

## DNS Protocol Compliance

- [X] DNSSEC validation (RRSIG verification) — assert the AD bit
  ourselves by verifying RRSIG signatures
- [X] ANY query handling (RFC 8482) — respond with HINFO or
  truncate, instead of forwarding and returning all record types
- [X] EDNS Client Subnet (ECS / RFC 7871) — forward client subnet
  to upstream for geo-aware responses
- [X] DNS64 / NAT64 (RFC 6147) — synthesize AAAA records from A
  responses for IPv6-only clients on NAT64 networks
- [ ] EDNS padding (RFC 7830) — add padding to EDNS options for
  privacy when using encrypted transports
- [ ] DNSSEC trust anchor management (RFC 5011) — automated
  maintenance of root trust anchor for real DNSSEC validation
- [ ] NSEC3 support — implement NSEC3 hash computation for
  authenticated denial of existence in authoritative zones
- [ ] DNSSEC key rollover (KSK/ZSK) — automated key rotation with
  overlap period for zero-downtime signing
- [X] DNS64 trigger A record lookup — when only a AAAA query arrives,
  proactively resolve the A record to enable synthesis

## Networking & Access Control

- [X] Authoritative DNS zones — full RFC 1035 zone file parsing;
  serve local zones with supported types (SOA, NS, A, AAAA,
  CNAME, MX, TXT, SRV, etc.)
- [X] DNSSEC signing for authoritative zones — RRSIG generation
  with ECDSA P-256/P-384, NSEC chain, DNSKEY inclusion
- [ ] Split-horizon DNS — respond differently based on client
  network (e.g., internal clients see RFC1918 addresses,
  external clients see public IPs)
- [X] Network-level ACLs — per-listener IP whitelist/blacklist:
  - ACL-based block/allowlists (subnet-scoped filtering)
  - ACL-based zone access (restrict which clients can query
    which zones)
  - ACL-based upstream selection (different upstreams per
    client subnet)
  - ACL-based protocol restrictions (e.g., only allow
    certain subnets to use TCP)
- [X] TCP connection limits per client — separate from query rate
  limiting; prevents TCP resource exhaustion
- [X] Configurable action for rate-limited queries — SERVFAIL vs
  silent drop
- [ ] Zone transfers (AXFR/IXFR) — support outbound zone transfers
  for secondary DNS replication
- [ ] DNS forwarding zones — delegate resolution for entire zones
  to specific upstreams (e.g., `corp.example.com` → internal resolver)
- [ ] DHCP integration — provide hostname resolution for LAN clients
  via DHCP lease information
- [ ] Response Rate Limiting (RRL) — limit identical responses to
  the same client to prevent amplification attacks (separate from
  query rate limiting)
- [ ] Token bucket rate limiting — burst support with configurable
  rate and burst size (replaces current fixed-window hard cap)
- [ ] Per-client statistics — track query patterns per client IP
  (top domains, blocked vs allowed, qtype distribution)

## Observability

- [X] Metrics package — comprehensive collectors (queries, cache,
  upstream, errors, blocking, DNSSEC, DNS64, ECS, zones)
- [X] Grafana dashboard — pre-built dashboard covering all metrics
- [X] Rotatable query log (CSV) — per-request log via PostResponse hook:
  client IP, query name/type, response RCODE, latency, cache decision,
  upstream used
- [X] pprof / debug endpoints — standard Go runtime profiling
  (CPU, memory, goroutine, mutex)
- [X] OpenTelemetry tracing — OTLP gRPC exporter, 4 span types
  (dns.query, dns.resolve, dns.upstream_query, dns.hook.<name>)

## Scaling & Multi-Node

- [X] Shared-state race condition audit — systematically review
  Valkey-based coordination for races (inflight dedup across
  nodes, rate-limit counter consistency, cache stampede prevention)
- [X] SO_REUSEPORT — allow multiple listener goroutines to share
  the same UDP/TCP port for better CPU utilization on multi-core
  systems
- [X] Instance identity — UUID per process, configurable NodeName/NodeID
- [X] Cross-node cache stampede prevention — distributed lock + poll
- [X] Cross-node stale-while-revalidate — distributed lock
- [X] Rate limit fail-close — on Valkey error, fail closed (SERVFAIL all)
  vs fail open (allow all)
- [X] Distributed lock package (lock/) — Valkey-based SET NX EX + Lua
  safe unlock; InProcessMutex fallback
- [X] Cross-node integration tests — 7 tests covering lock correctness,
  stampede prevention, stale-revalidate, rate-limit counters, cache
  flush propagation, cache coordination, DNS query through 2 nodes

## Extended Testing & Benchmarking

- [X] Output comparison test — forward the same query set to
  9.9.9.9, 8.8.8.8, and 1.1.1.1; verify our response matches
  (allowing for TTL differences)
- [X] Build a curated list of ~1000 domains — mix of popular,
  niche, internationalized, and edge-case domains
- [X] "Blast" test — 1000 concurrent queries on a single CPU core;
  measure throughput, latency distribution, error rate, and
  cache effectiveness
- [X] Benchmarks — 6 benchmarks (resolve cache hit/miss/NXDOMAIN,
  parse message, pack message, concurrent resolve)
- [X] Shared test utilities — MockUpstream, DNS builders, factories
- [X] Fuzz tests — 3 fuzz functions (parse message, compression pointers,
  write/read name)
- [X] RFC correctness tests — EDNS version negotiation, truncation,
  unknown RR types, special-use domains, negative caching, class
  handling, name compression


# northstar — Build Phases

> Prioritized sequential phases. Each phase depends on the previous;
> items within a phase are unordered and can be tackled in any order.

## Phase 1: Foundation & Architecture

**Goal:** Unlock configuration-driven operation and clean up the request
path before piling on features.

- [X] YAML config file with env var override hierarchy
  (file < env var < API)
- [X] Hot-reload config on SIGHUP
- [X] Middleware & Hooks pipeline — refactor hardcoded rate limiting into
  a hook, define lifecycle points (pre-resolve, post-resolve,
  pre-response, post-response) with enable/disable and ordering

**Depends on:** nothing (pure new code + refactor)

---

## Phase 2: Cache & Core Correctness

**Goal:** Production-grade caching — prevent unbounded memory growth,
cache negative answers, give operators TTL control.

- [X] Negative caching (RFC 2308) — NXDOMAIN and NODATA
- [X] Cache size limits by entry count with LRU eviction
- [X] Cache hit counter + last-hit timestamp
- [X] TTL Overwrite (configurable min/max)
- [X] TCP connection limits per client
- [X] Configurable action for rate-limited queries (SERVFAIL / drop)
- [X] bbolt file-based cache backend (Low RAM Mode)
- [X] Cache warming on startup (from Valkey or bbolt)

**Depends on:** Phase 1 (hooks for rate-limit action config)

---

## Phase 3: Upstream Management

**Goal:** Multiple upstreams with health checking, failover, concurrent
forwarding, and intelligent routing.

- [X] Multiple upstream entries in config + runtime
- [X] Health checking with automatic failover
- [X] Concurrent forwarding (configurable concurrency)
- [X] Periodic speed assessment + prefer fastest
- [X] Upstream priorities (primary / fallback tiers)
- [X] Adaptive timeouts per upstream
- [X] Conditional forwarding (`*.internal.corp` → private resolver)

**Depends on:** Phase 1 (config file), Phase 2 (TCP limits for upstream)

---

## Phase 4: Blocking & Filtering

**Goal:** DNS-level content filtering with flexible policy.

- [X] Blocklists (file-based, wildcard support)
- [X] Allowlists (takes precedence)
- [X] Configurable block action (NXDOMAIN / sinkhole / REFUSED / drop)
- [X] Hot-reload blocklist/allowlist files (SIGHUP)
- [X] Response Policy Zones (RPZ)
- [X] Per-domain rate limiting
- [X] Blocklist format compatibility (AdGuard Home, Pi-hole)

**Depends on:** Phase 1 (config file, hooks pipeline)

---

## Phase 5: Transport Security

**Goal:** Encrypted DNS transports for both client-facing and upstream
communication.

- [X] Reverse Proxy integration (i.e. Caddy or Traefik)
- [X] DNS-over-TLS (DoT) — upstream + listener
- [X] DNS-over-HTTPS (DoH) — upstream + listener
- [X] DNS-over-QUIC (DoQ) — upstream + listener
- [X] QNAME Minimization

**Depends on:** Phase 1 (config file for TLS cert paths, upstream URLs)

---

## Phase 6: DNS Protocol

**Goal:** Full protocol compliance beyond basic forwarding.

- [X] DNSSEC validation (RRSIG verification)
- [X] ANY query handling (RFC 8482)
- [X] EDNS Client Subnet (RFC 7871)
- [X] DNS64 / NAT64 (RFC 6147)

**Depends on:** Phase 1 (config file for policy flags)

---

## Phase 7: API

**Goal:** Remote management via REST API.

- [X] REST API (CRUD upstreams, blocklists, cache, system info)
  - System endpoints: health, status, config
  - Upstream CRUD: list, get, create, update, delete with YAML persistence
  - Blocklist/allowlist: paths, counts, reload, test, stats
  - Cache: stats, flush, delete by domain/qtype, inspect entry
  - API key auth via `X-API-Key` header
  - Config fields: `APIEnable`, `APIPort` (9163), `APIKey` with env overrides
  - Cache interface extended: `Delete`, `DeleteDomain`, `Len`, `Evictions`

**Depends on:** Phase 3 (upstreams to manage), Phase 4 (blocklists to manage),
Phase 5 (transport config), Phase 6 (DNSSEC config)

---

## Phase 8: Advanced Networking

**Goal:** Act as an authoritative server and enforce network-level policy.

- [X] Authoritative DNS zones (RFC 1035)
  - `zone/` package — types, RData wire format, config parsing, response building
  - Structured record config (A, AAAA, CNAME, NS, MX, SOA, TXT, SRV, DNSKEY, RRSIG, NSEC)
  - `AuthoritativeHook` (PreResolve, prio 50) — intercepts zone queries before forwarding
  - Longest-suffix zone matching, NXDOMAIN/NODATA responses with SOA authority
  - Config YAML `zones` field with structured per-type record fields
  - Full CRUD via API: `GET/POST/PUT/DELETE /api/v1/zones` + `{name}` and `/reload`
- [X] DNSSEC signing for authoritative zones
  - RRSIG generation with ECDSA P-256/P-384 key loading
  - NSEC chain building for authenticated denial of existence
  - DNSKEY record inclusion in responses when DO bit set
  - Auto-generate signing key if no key file configured
  - Config fields: `algorithm`, `key_file`, `zsk_file`, `nsec3`
- [X] Network-level ACLs (block/allow, zone access, upstream routing,
  protocol restrictions)
  - `acl/` package — `Rule` and `RuleSet` with client subnet, zone, protocol, upstream matching
  - `AclHook` (PreResolve, prio 150) — allow/refuse/drop/route actions
  - Route action sets `ctx.PreferredUpstream` for targeted upstream selection
  - Config YAML `acls` field with subnet/zone/protocol/upstream scoping
  - Full CRUD via API: `GET/POST/PUT/DELETE /api/v1/acls` + `{name}`
- [X] `upstream.Group.GetByName()` method for ACL route lookups
- [X] Hot-reload SIGHUP: zones and ACLs rebuilt on config reload

**Depends on:** Phase 1 (config file, hooks), Phase 3 (upstream ACLs),
Phase 6 (zone serving), Phase 7 (zone management via API)

---

## Phase 9: Observability

**Goal:** Deep insight into server behavior.

- [X] Sub-phase 9.1 — pprof / debug endpoints
  - Import `net/http/pprof`, mount `/debug/pprof/` on metrics HTTP server
  - Config: `debug_enable` (bool, default false)
- [X] Sub-phase 9.2 — Metrics package cleanup & additions
  - Remove dead collectors, wire `UpstreamConditionalHits`
  - New collectors: `CacheEvictionsTotal`, `NegativeCacheLookups`,
    `NegativeCacheHits`, `ZoneQueriesTotal`
- [X] Sub-phase 9.3 — Rotatable query log hook
  - CSV format: `timestamp,client_ip,qname,qtype,rcode,latency_ms,cache_decision,upstream`
  - Daily rotation, configurable retention
- [X] Sub-phase 9.4 — Grafana dashboard
  - Pre-built `grafana/dashboard.json`, `prometheus.yml` scrape config

**Depends on:** Phase 1 (hooks for query log), Phase 3+ (metrics for
upstreams, zones), Phase 7 (metrics in API)

---

## Phase 10: Scaling & Multi-Node

**Goal:** Safe multi-instance deployments and better CPU utilization.

- [X] Instance identity (node/ package) — UUID per process, configurable NodeName/NodeID, exposed via API/status
- [X] Distributed lock package (lock/) — Valkey-based mutex with SET NX EX + Lua safe unlock; InProcessMutex fallback
- [X] Cross-node cache stampede prevention — distributed lock before upstream fetch; losers poll Peek() with backoff
- [X] Cross-node stale-while-revalidate — distributed lock elects one refresher per stale entry; others skip
- [X] Cache flush API fix — `Cache.Flush()` interface method
- [X] Rate limit fail-close option — `RateLimitFailClose` config
- [X] SO_REUSEPORT — ListenConfig with Control function; configurable worker count
- [X] Config: ReusePort, ReusePortWorkers, NodeName, NodeID, RateLimitFailClose
- [X] Setups for MultiNode SameHost and DifferentHosts (Docker Compose)
- [X] Extended tests for lock (6 tests), SO_REUSEPORT (3 tests)

**Depends on:** Phase 2 (bbolt for Valkey alternatives), everything else
feature-complete enough to audit meaningfully

---

## Phase 11: Extended Testing

**Goal:** Confidence in correctness and performance under load.

- [X] Output comparison test (9.9.9.9, 8.8.8.8, 1.1.1.1) — `resolver/output_test.go`, build tag `integration`
- [X] Curated 1000-domain test list — `resolver/testdata/domains.go`
- [X] Blast test (1000 concurrent queries, 1 CPU core) — `resolver/blast_test.go`
- [X] Benchmarks — `resolver/bench_test.go`, 6 benchmarks
- [X] Shared test utilities — `internal/testutil/testutil.go`
- [X] Justfile updates — `test-fast`, `test-cover`, `test-all`, `test-blast`, `bench` recipes

**Depends on:** All features deployed and stable

---

## Phase 12: RFC correctness

**Goal:** Correctness for relevant RFCs and other Web standards.

- [X] EDNS Version Negotiation (RFC 3425)
- [X] Truncation Correctness (RFC 1035 §6.2)
- [X] Unknown RR Types (RFC 3597) — TYPE=65432 round-trips through Parse/Pack
- [X] Special-Use Domain Handling (RFC 6761) — `SpecialDomainHook` with 9 tests
- [X] Negative Caching Audit (RFC 2308) — fixed `NewEntry()` RCode storage, 3 tests
- [X] Class Handling — non-IN classes return REFUSED
- [X] Name Compression Edge Cases — reserved label types rejected
- [X] Valkey-backed Integration Tests — 9 tests with `//go:build integration` tag
- [X] Fuzz Tests — 3 fuzz functions, 380k+ execs, 29 interesting cases, no crashes

**Depends on:** All features deployed and stable

---

## Phase 13: Distributed Tracing

**Goal:** End-to-end distributed trace visibility for multi-node deployments.

### Sub-phase 13A — Cross-Node Integration Tests

- [X] docker-compose.test.yml — 2 northstar instances + 1 Valkey
- [X] 7 tests: lock correctness, stampede prevention, stale-revalidate,
  rate-limit counters, cache flush propagation, cache coordination,
  DNS query through 2 nodes

### Sub-phase 13B — OpenTelemetry Tracing

- [X] Config: `tracing` block with `enable`, `endpoint`, `service_name`, `sample_rate`
- [X] `tracing/tracing.go` package — OTLP gRPC exporter, batch span processor
- [X] Wiring in `main.go` — init tracer, `SetTracer()`, graceful shutdown
- [X] Spans: `dns.query`, `dns.resolve`, `dns.upstream_query`, `dns.hook.<name>`
- [X] Context propagation through hook `Context.Ctx`
- [X] Config tests: defaults, env overrides, file config, env > file hierarchy
- [X] Tracing package tests: disabled (noop tracer), nil safety, invalid endpoint error handling

**Depends on:** Phase 9 (observability foundation — metrics, logging),
Phase 10 (multi-node deployment to benefit from tracing)

---

## Phase 14: Caching & Performance

**Goal:** Smarter caching with adaptive prefetch, persistence, and performance tuning.

- [X] Adaptive prefetch / Keep warm — proactively refresh popular entries
  before they expire (configurable popularity threshold and prefetch window)
- [X] Cache persistence to disk on shutdown — save in-memory cache entries
  to a file on `SIGTERM`/`SIGINT` for warm restart
- [X] Aggressive negative TTL override — configurable floor/cap for
  negative TTL that overrides the SOA minimum field
- [X] DNS64 trigger A record lookup — when only a AAAA query arrives
  and DNS64 is active, proactively resolve the A record first to
  enable synthesis
- [X] Parallel zone parsing — parse authoritative zone files concurrently
  at startup to reduce cold-start latency

**Depends on:** Phase 2 (cache system), Phase 6 (DNS64)

---

## Phase 15: Blocking & Filtering Enhancement

**Goal:** Modern blocklist management with remote sources and analytics.

- [X] URL-based blocklist sources — auto-download blocklists from URLs
  with periodic refresh (configurable interval), local caching of
  downloaded files, and atomic swap on update
- [X] Ad blocking analytics / reporting — top blocked domains, top
  blocked clients, blocked-vs-allowed ratios, daily trend data
  exposed via API

**Depends on:** Phase 4 (existing blocking and filtering), Phase 7 (API)

---

## Phase 16: Rate Limiting & Access Control

**Goal:** Sophisticated rate limiting and network-level policy enforcement.

- [X] Response Rate Limiting (RRL) — limit identical responses to the
  same client to prevent DNS amplification attacks (separate from
  existing query rate limiting)
- [X] Token bucket rate limiting — burst support with configurable
  rate and burst size (replaces current fixed-window hard cap)
- [X] Per-client statistics — track query patterns per client IP
  (top domains, blocked vs allowed, qtype distribution) exposed
  via API
- [X] Split-horizon DNS — respond differently based on client network
  (e.g., internal clients see RFC1918 addresses, external clients
  see public IPs)

**Depends on:** Phase 1 (hooks pipeline), Phase 7 (API), Phase 8 (ACLs)

---

## Phase 17: DNS Protocol Enhancements

**Goal:** Deeper protocol compliance and DNSSEC lifecycle management.

- [X] EDNS padding (RFC 7830) — add configurable padding to EDNS
  options for query privacy over encrypted transports
- [X] DNSSEC trust anchor management (RFC 5011) — automated
  maintenance of root trust anchor with RFC 5011 compliant
  key rollover tracking
- [X] NSEC3 support — implement NSEC3 hash computation (SHA-1
  with configurable iterations and salt) for authenticated
  denial of existence in authoritative zones
- [X] DNSSEC key rollover (KSK/ZSK) — automated key rotation with
  overlap period, DS record publication timing, and zero-downtime
  re-signing of zone records

**Depends on:** Phase 6 (DNSSEC validation), Phase 8 (zone signing)

---

## Phase 18: Upstream & Transport Enhancements

**Goal:** Better upstream connectivity options and efficiency.

- [ ] HTTP CONNECT proxy support for DoH upstream — tunnel outbound
  DoH queries through an HTTP CONNECT proxy for environments with
  egress proxy requirements
- [ ] HTTP/2 connection coalescing for DoH upstream — reuse a single
  HTTP/2 connection for multiple concurrent queries to the same
  DoH upstream (reduces connection overhead)

**Depends on:** Phase 5 (DoH upstream implementation)

---

## Phase 19: Zone & Networking Extensions

**Goal:** Full authoritative DNS functionality and advanced routing.

- [ ] Zone transfers (AXFR/IXFR) — support outbound zone transfers
  for secondary DNS replication (TSIG-signed transfer requests)
- [ ] DNS forwarding zones — delegate resolution for entire zones
  to specific upstreams (e.g., `corp.example.com` → internal
  resolver), with configurable forward-only vs forward-first
  semantics
- [ ] DHCP integration — consume DHCP lease information to provide
  hostname resolution for LAN clients without requiring static
  zone configuration

**Depends on:** Phase 8 (authoritative zones, ACLs)

---

## Phase 20: Tooling & Configuration

**Goal:** Better developer and operator ergonomics.

- [ ] Configuration validation command — `northstar check-config`
  that validates the YAML config file and reports all errors
  before the server starts
- [ ] TOML config file support — add TOML as an alternative config
  format with identical field mapping, override hierarchy, and
  auto-generation

**Depends on:** Phase 1 (config system)

---

## Phase 21: Advanced / Nice-to-Have

**Goal:** Power-user features for custom logic and environment integration.

- [ ] Lua scripting for custom logic — embed a Lua runtime with
  hooks exposed at all lifecycle points (pre-resolve, post-resolve,
  pre-response, post-response) for arbitrary query manipulation
  without recompiling the server

**Depends on:** Phase 1 (hooks pipeline)
