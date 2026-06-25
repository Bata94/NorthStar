# northstar — Roadmap

> Comprehensive list of planned features. Prioritization TBD — this is the
> complete set before ordering by milestone.

## Transport Security & Privacy

- DNS-over-HTTPS (DoH) — both upstream and client-facing listener
- DNS-over-TLS (DoT) — both upstream and client-facing listener
- DNS-over-QUIC (DoQ) — both upstream and client-facing listener
- QNAME Minimization — strip labels from query name before forwarding
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

- Blocklists — file-based, one domain per line, wildcard/glob support
  (`*.example.com`)
- Allowlists — takes precedence over blocklists
- Configurable block action — NXDOMAIN / 0.0.0.0 sinkhole / REFUSED /
  drop silently
- Hot-reload blocklist/allowlist files — inotify-based reload without
  restart
- Response Policy Zones (RPZ) — more sophisticated blocking via
  policy zone files (compatible with common RPZ feeds)
- Blocklist format compatibility — optionally consume AdGuard Home and
  Pi-hole list formats
- Per-domain rate limiting — limit queries to specific domains (e.g.,
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
- WebUI — browser-based management dashboard consuming the REST API

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

- Revisit metrics package — add per-upstream latency,
  per-zone query counts, cache eviction rate, negative cache
  stats, blocklist hit counters
- OpenTelemetry tracing — distributed trace propagation for
  end-to-end query visibility
- Tailored Grafana dashboard — pre-built dashboard covering
  all metrics
- Rotatable query log — per-request log: client IP, query
  name/type, response RCODE, latency, cache decision (hit/miss/stale),
  upstream used
- pprof / debug endpoints — standard Go runtime profiling
  (CPU, memory, goroutine, mutex)

## Scaling & Multi-Node

- Shared-state race condition audit — systematically review
  Valkey-based coordination for races (inflight dedup across
  nodes, rate-limit counter consistency, cache stampede prevention)
- SO_REUSEPORT — allow multiple listener goroutines to share
  the same UDP/TCP port for better CPU utilization on multi-core
  systems

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

- [ ] Multiple upstream entries in config + runtime
- [ ] Health checking with automatic failover
- [ ] Concurrent forwarding (configurable concurrency)
- [ ] Periodic speed assessment + prefer fastest
- [ ] Upstream priorities (primary / fallback tiers)
- [ ] Adaptive timeouts per upstream
- [ ] Conditional forwarding (`*.internal.corp` → private resolver)

**Depends on:** Phase 1 (config file), Phase 2 (TCP limits for upstream)

---

## Phase 4: Blocking & Filtering

**Goal:** DNS-level content filtering with flexible policy.

- [ ] Blocklists (file-based, wildcard support)
- [ ] Allowlists (takes precedence)
- [ ] Configurable block action (NXDOMAIN / sinkhole / REFUSED / drop)
- [ ] Hot-reload blocklist/allowlist files (inotify)
- [ ] Response Policy Zones (RPZ)
- [ ] Per-domain rate limiting
- [ ] Blocklist format compatibility (AdGuard Home, Pi-hole)

**Depends on:** Phase 1 (config file, hooks pipeline)

---

## Phase 5: Transport Security

**Goal:** Encrypted DNS transports for both client-facing and upstream
communication.

- [ ] Reverse Proxy integration (i.e. Caddy or Traefik)
- [ ] DNS-over-TLS (DoT) — upstream + listener
- [ ] DNS-over-HTTPS (DoH) — upstream + listener
- [ ] DNS-over-QUIC (DoQ) — upstream + listener
- [ ] QNAME Minimization

**Depends on:** Phase 1 (config file for TLS cert paths, upstream URLs)

---

## Phase 6: DNS Protocol

**Goal:** Full protocol compliance beyond basic forwarding.

- [ ] DNSSEC validation (RRSIG verification)
- [ ] ANY query handling (RFC 8482)
- [ ] EDNS Client Subnet (RFC 7871)
- [ ] DNS64 / NAT64 (RFC 6147)

**Depends on:** Phase 1 (config file for policy flags)

---

## Phase 7: API & WebUI

**Goal:** Remote management and visibility.

- [ ] REST API (CRUD upstreams, blocklists, zones, cache, runtime config)
- [ ] WebUI consuming the REST API

**Depends on:** Phase 3 (upstreams to manage), Phase 4 (blocklists to manage),
Phase 5 (transport config), Phase 6 (DNSSEC config)

---

## Phase 8: Advanced Networking

**Goal:** Act as an authoritative server and enforce network-level policy.

- [ ] Authoritative DNS zones (RFC 1035)
- [ ] Split-horizon DNS
- [ ] Network-level ACLs (block/allow, zone access, upstream selection,
  protocol restrictions)

**Depends on:** Phase 1 (config file, hooks), Phase 3 (upstream ACLs),
Phase 6 (zone serving), Phase 7 (zone management via API)

---

## Phase 9: Observability

**Goal:** Deep insight into server behavior.

- [ ] Metrics package revisit (per-upstream, per-zone, cache eviction,
  negative cache, blocklist stats)
- [ ] OpenTelemetry tracing
- [ ] Grafana dashboard
- [ ] Rotatable query log (via hooks)
- [ ] pprof / debug endpoints

**Depends on:** Phase 1 (hooks for query log), Phase 3+ (metrics for
upstreams, zones), Phase 7 (metrics in API)

---

## Phase 10: Scaling & Multi-Node

**Goal:** Safe multi-instance deployments and better CPU utilization.

- [ ] Shared-state race condition audit (Valkey coordination)
- [ ] SO_REUSEPORT
- [ ] Setups for MutliNode SameHost and DifferentHosts

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
