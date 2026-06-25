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
- [ ] Keep top entries warm / Adaptive prefetch — proactively refresh
  popular entries before they expire (configurable popularity threshold
  and prefetch window)
- [X] TTL Overwrite — global min/max TTL override to reduce upstream
  queries (e.g., floor at 30s, cap at 1h)
- [X] Negative caching (RFC 2308) — cache NXDOMAIN and NODATA responses
  with separate (typically shorter) TTLs; currently only successful
  responses are cached
- [X] Cache warming on startup — reload popular entries from Valkey or
  bbolt on restart to avoid a cold-cache storm

## Upstream Management

- Concurrent forwarding — query multiple upstreams in parallel with
  configurable concurrency; return first valid response
- Periodic speed assessment — measure upstream latency periodically
  and prefer the fastest N upstreams automatically
- Upstream priorities — primary / fallback tiers with automatic
  promotion/demotion
- Health checking with automatic failover — periodic health probes
  (e.g., query `.' or a configurable test domain); remove unhealthy
  upstreams from rotation
- Conditional forwarding — route by domain suffix
  (e.g., `*.internal.corp` → private resolver)
- Adaptive timeouts per upstream — track historical latency and
  adjust timeouts dynamically per upstream

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

## Low RAM Mode

- [X] File-based cache backend (bbolt) — on-disk storage, minimal memory
  footprint
- [X] Environment variable toggle — `NORTHSTAR_CACHE_FILE` to enable;
  falls back to current memory/Valkey logic when unset
- [X] Periodic expiry compaction — bbolt auto-compaction to reclaim space

## Configuration & API

- REST API — focused on serving the WebUI, but fully usable from
  external programs for programmatic control (CRUD upstreams,
  blocklists, zones, cache operations, runtime config)
- YAML/TOML config file — single source of truth with env var
  override hierarchy (file < env var < API)
- Hot-reload on SIGHUP — re-read config file without restart

## Middleware & Hooks System

- Plugin-like hook pipeline — pre-defined lifecycle points:
  pre-resolve, post-resolve, pre-response, post-response
- Built-in hook implementations:
  - Rate limiting (replaces current hardcoded check)
  - ACL evaluation
  - Blocklist / Allowlist filtering
  - QNAME minimization
  - Query logging
- Users can enable/disable and reorder hooks via config

## DNS Protocol Compliance

- DNSSEC validation (RRSIG verification) — currently only
  passes AD/DO bits through; add actual signature verification
  to assert the AD bit ourselves
- ANY query handling (RFC 8482) — respond with HINFO or
  truncate, instead of forwarding and returning all record types
- EDNS Client Subnet (ECS / RFC 7871) — forward client subnet
  to upstream for geo-aware responses
- DNS64 / NAT64 (RFC 6147) — synthesize AAAA records from A
  responses for IPv6-only clients on NAT64 networks

## Networking & Access Control

- Authoritative DNS zones — full RFC 1035 zone file parsing;
  serve local zones with supported types (SOA, NS, A, AAAA,
  CNAME, MX, TXT, SRV, etc.)
- Split-horizon DNS — respond differently based on client
  network (e.g., internal clients see RFC1918 addresses,
  external clients see public IPs)
- Network-level ACLs — per-listener IP whitelist/blacklist:
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
  silent drop (currently hardcoded to SERVFAIL)

## Observability

- [X] Metrics package cleanup — remove dead collectors, add missing
  counters (cache evictions, negative cache stats, per-zone queries)
- [X] Grafana dashboard — pre-built dashboard covering all metrics
- [X] Rotatable query log (CSV) — per-request log via PostResponse hook:
  client IP, query name/type, response RCODE, latency, cache decision,
  upstream used
- [X] pprof / debug endpoints — standard Go runtime profiling
  (CPU, memory, goroutine, mutex)
- OpenTelemetry tracing (deferred to Phase 13)

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

## Extended Testing & Benchmarking

- Output comparison test — forward the same query set to
  9.9.9.9, 8.8.8.8, and 1.1.1.1; verify our response matches
  (allowing for TTL differences)
- Build a curated list of ~1000 domains — mix of popular,
  niche, internationalized, and edge-case domains
- "Blast" test — 1000 concurrent queries on a single CPU core;
  measure throughput, latency distribution, error rate, and
  cache effectiveness


# northstar — Build Phases

> Prioritized sequential phases. Each phase depends on the previous;
> items within a phase are unordered and can be tackled in any order.

## Phase 1: Foundation & Architecture

**Goal:** Unlock configuration-driven operation and clean up the request
path before piling on features.

- [X] YAML/TOML config file with env var override hierarchy
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
  - Fixed `dns.ParseRRSIG` (ignored readName offset, caused "truncated after signer name")
- [ ] Split-horizon DNS (deferred to later phase)
- [X] Network-level ACLs (block/allow, zone access, upstream routing,
  protocol restrictions)
  - `acl/` package — `Rule` and `RuleSet` with client subnet, zone, protocol, upstream matching
  - `AclHook` (PreResolve, prio 150) — allow/refuse/drop/route actions
  - Route action sets `ctx.PreferredUpstream` for targeted upstream selection
  - `PreferredUpstream` field in hooks context, passed through resolve()
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
  - Files: `main.go`, `config/config.go`, `config/config_file.go`
- [X] Sub-phase 9.2 — Metrics package cleanup & additions
  - Remove dead collectors: `UpstreamConcurrentWins`
  - Wire `UpstreamConditionalHits` into conditional route matching in `upstream/upstream.go`
  - New collectors:
    - `CacheEvictionsTotal` (Counter, label `backend`) — wired in `cache/cache.go`, `cache/valkey.go`, `cache/bbolt.go`
    - `NegativeCacheLookups` (Counter) — wired in `resolver/resolver.go` on cache peek
    - `NegativeCacheHits` (Counter) — wired in `resolver/resolver.go` on negative cache hit
    - `ZoneQueriesTotal` (CounterVec, labels `zone`, `qtype`) — wired in `hooks/authoritative.go`
- [X] Sub-phase 9.3 — Rotatable query log hook
  - New hook: `hooks/querylog.go` — `"query_log"`, PostResponse lifecycle, priority 900
  - CSV format: `timestamp,client_ip,qname,qtype,rcode,latency_ms,cache_decision,upstream`
  - Reuses `log.RotateWriter` for daily rotation
  - Config: `QueryLogEnable`, `QueryLogFile` (`./query.log`), `QueryLogRetention` (7 days)
  - Add `StartTime` field to `hooks.Context`
- [X] Sub-phase 9.4 — Grafana dashboard
  - Create `grafana/dashboard.json` — panels for: query rate, cache hit ratio, upstream latency, upstream health, error rate, active handlers, blocked queries, DNSSEC validation, zone queries, cache evictions
  - Create `prometheus.yml` scrape config
  - Document in `README.md`

**Depends on:** Phase 1 (hooks for query log), Phase 3+ (metrics for
upstreams, zones), Phase 7 (metrics in API)

---

## Phase 10: Scaling & Multi-Node

**Goal:** Safe multi-instance deployments and better CPU utilization.

- [X] Instance identity (node/ package) — UUID per process, configurable NodeName/NodeID, exposed via API/status
- [X] Distributed lock package (lock/) — Valkey-based mutex with SET NX EX + Lua safe unlock; InProcessMutex fallback for non-Valkey backends
- [X] Cross-node cache stampede prevention — distributed lock before upstream fetch; losers poll Peek() with backoff
- [X] Cross-node stale-while-revalidate — distributed lock elects one refresher per stale entry; others skip
- [X] Cache flush API fix — replaced broken `s.cache = cache.NewMemory(0, nil)` with `Cache.Flush()` interface method
- [X] Rate limit fail-close option — `RateLimitFailClose` config; on Valkey error, fail closed (SERVFAIL all) vs fail open (allow all)
- [X] SO_REUSEPORT — ListenConfig with Control function; configurable worker count (default 1)
- [X] Config: ReusePort, ReusePortWorkers, NodeName, NodeID, RateLimitFailClose
- [X] Setups for MultiNode SameHost and DifferentHosts (Docker Compose)
- [X] Extended tests for lock (6 tests), SO_REUSEPORT (3 tests: UDP+TCP listen, disabled Control, GetsockoptInt verification)

**Depends on:** Phase 2 (bbolt for Valkey alternatives), everything else
feature-complete enough to audit meaningfully

---

## Phase 11: Extended Testing

**Goal:** Confidence in correctness and performance under load.

- [ ] Output comparison test (9.9.9.9, 8.8.8.8, 1.1.1.1)
- [ ] Curated 1000-domain test list
- [ ] Blast test (1000 concurrent queries, 1 CPU core)

**Depends on:** All features deployed and stable

---

## Phase 12: RFC correctness

**Goal:** Correctness for relevant RFCs and other Web standards

- [ ] Find all relevant RFCs and other Web standards
- [ ] Implement and test against them

**Depends on:** All features deployed and stable

---

## Phase 13: Distributed Tracing

**Goal:** End-to-end distributed trace visibility for multi-node deployments.

- [ ] OpenTelemetry integration
  - Dependencies: `go.opentelemetry.io/otel`, SDK, OTLP exporter (gRPC/HTTP)
  - Config: `tracing_enable`, `tracing_endpoint` (`localhost:4317`),
    `tracing_service_name` (`northstar`), `tracing_sample_rate` (0.1)
  - Spans at key points:
    - `dns.query` — wraps `processQuery`; tags: client_ip, qname, qtype, rcode
    - `dns.cache_lookup` — sub-span; tags: hit/miss, stale
    - `dns.upstream_query` — sub-span; tags: upstream_name, latency_ms
    - `dns.hook.<name>` — sub-span per hook execution; tags: lifecycle, hook_name
  - Context propagation through hook `Context`
  - OTLP exporter to OpenTelemetry Collector / Grafana Tempo / Jaeger

**Depends on:** Phase 9 (observability foundation — metrics, logging),
Phase 10 (multi-node deployment to benefit from tracing)
