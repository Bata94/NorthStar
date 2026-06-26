# NorthStar

[![Go](https://img.shields.io/badge/Go-1.26.2-blue?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT_+_Commons_Clause-yellow)](#license)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/bata94/northstar/pulls)
[![Go Reference](https://pkg.go.dev/badge/github.com/bata94/northstar.svg)](https://pkg.go.dev/github.com/bata94/northstar)
[![Go Report Card](https://goreportcard.com/badge/github.com/bata94/northstar)](https://goreportcard.com/report/github.com/bata94/northstar)

A lightweight, high-performance recursive DNS forwarder with on-device caching, per-client rate limiting, DNSSEC validation, authoritative zones, encrypted transports (DoT/DoH/DoQ), a REST API, and a hook-based middleware pipeline. Designed as an alternative to Technitium, AdGuard Home, or Pi-hole for users who want full visibility and control over their DNS infrastructure.

Disclaimer: This is a prototype. A lot of it is AI-coded as a proof of concept. The goal is to land all features first, then refactor to production quality once the design is validated.
Until v1.0.0 changes are rapid and not checked for backwards-compatibility! Development is done in the main branch. After v1.0.0, feature branches with stable patch releases and potentially breaking changes in minor/major releases.

Built for Docker, configured via YAML and environment variables, instrumented with Prometheus and OpenTelemetry out of the box.

## Features

### DNS Forwarding & Upstream Management
- **DNS forwarding** — queries forwarded to any upstream resolver over UDP, TCP, TLS, DoH, or DoQ
- **Multiple upstreams** — configure multiple resolvers with priority tiers (primary/fallback)
- **Health checking** — periodic probes with automatic failover; unhealthy upstreams removed from rotation
- **Concurrent forwarding** — query multiple upstreams in parallel; return first valid response
- **Speed assessment** — periodic EWMA latency measurement; automatically prefer fastest upstreams
- **Adaptive timeouts** — per-upstream timeouts based on historical latency
- **Conditional forwarding** — route by domain suffix (e.g., `*.internal.corp` → private resolver)
- **Upstream connection pooling** — reusable UDP and TCP connections with configurable idle limits

### Caching
- **In-memory or Valkey-backed cache** — shared cache for multi-instance deployments
- **bbolt file-based cache** — on-disk storage for low RAM mode (`NORTHSTAR_CACHE_FILE`)
- **Negative caching (RFC 2308)** — cache NXDOMAIN and NODATA with separate TTLs
- **TTL overwrite** — configurable global min/max TTL
- **LRU eviction** — configurable max entry count evicts oldest + least-used entries
- **Hit counter + last-hit timestamp** — per-entry access patterns
- **Stale-while-revalidate** — serve stale entries while refreshing in background
- **Cache warming on startup** — reload popular entries from Valkey or bbolt
- **Cache stampede prevention** — cross-node distributed lock + poll for thundering herd avoidance

### Blocking & Filtering
- **Blocklists** — file-based, one domain per line, wildcard support (`*.example.com`)
- **Allowlists** — takes precedence over blocklists
- **Configurable block action** — NXDOMAIN / sinkhole (127.0.0.1) / REFUSED / silent drop
- **Response Policy Zones (RPZ)** — policy zone file support
- **Format compatibility** — AdGuard Home (`||example.com^`) and Pi-hole (`0.0.0.0 example.com`) formats
- **Per-domain rate limiting** — limit queries to specific domains to prevent DDoS amplification
- **Hot-reload** — SIGHUP reloads filter files without restart

### Authoritative DNS Zones
- **Full RFC 1035 zone serving** — SOA, NS, A, AAAA, CNAME, MX, TXT, SRV records
- **Longest-suffix matching** — zone lookup by most specific parent domain
- **DNSSEC signing** — RRSIG generation with ECDSA P-256/P-384, NSEC chain, DNSKEY inclusion
- **Auto-generated signing keys** — if no key file configured
- **Full CRUD via API** — manage zones at runtime

### Encrypted Transports
- **DNS-over-TLS (DoT)** — client-facing listener + upstream support on port 853
- **DNS-over-HTTPS (DoH)** — client-facing listener + upstream support on port 443
- **DNS-over-QUIC (DoQ)** — client-facing listener + upstream support on port 853
- **Auto self-signed certificates** — generated on first run (ECDSA P-256, valid 1 year)

### DNS Protocol
- **DNSSEC validation** — RRSIG verification with "required" or "opportunistic" mode
- **DNSSEC passthrough** — preserves DO and AD bits between client and upstream
- **ANY query handling (RFC 8482)** — respond with HINFO instead of forwarding
- **EDNS Client Subnet (ECS / RFC 7871)** — forward client subnet for geo-aware responses
- **DNS64 / NAT64 (RFC 6147)** — synthesize AAAA records for IPv6-only clients
- **QNAME minimization** — strip labels before forwarding to reduce disclosure
- **Special-use domain handling (RFC 6761)** — localhost, invalid, test, example, local
- **EDNS0** — respects client payload size; truncates with TC bit when necessary

### Access Control
- **Network-level ACLs** — per-listener IP whitelist/blacklist
  - Block/allow by client subnet (CIDR)
  - Zone-restricted access (which clients can query which zones)
  - Upstream routing (different upstreams per client subnet)
  - Protocol restrictions (limit certain subnets to UDP only)
- **Per-client rate limiting** — fixed-window counters, shareable across instances via Valkey
- **TCP connection limits per client** — separate from query rate limiting
- **Configurable action** — SERVFAIL or silent drop for rate-limited queries

### REST API
- **System** — health, status, config endpoints
- **Upstreams** — CRUD upstream resolvers with YAML persistence
- **Cache** — stats, inspect, flush, delete by domain/qtype
- **Blocking** — list blocklists/allowlists, reload, test domain, stats
- **Zones** — CRUD authoritative zones
- **ACLs** — CRUD access control rules
- **Auth** — `X-API-Key` header or `?api_key=` query parameter
- **Port** — 9163 (configurable)

### Observability
- **Prometheus metrics** — 18+ collectors (queries, cache, upstream, blocking, DNSSEC, DNS64, ECS, zones)
- **OpenTelemetry tracing** — OTLP gRPC exporter with 4 span types (query, resolve, upstream, hook)
- **pprof debug endpoints** — CPU, memory, goroutine, mutex profiling
- **Rotatable query log (CSV)** — per-request log via PostResponse hook with daily rotation
- **Grafana dashboard** — pre-built at [`grafana/dashboard.json`](grafana/dashboard.json)
- **Structured logging** — colored console in dev mode, JSON file for production

### Multi-Node & Scaling
- **SO_REUSEPORT** — multiple listener goroutines sharing the same port for better CPU utilization
- **Instance identity** — UUID per process, configurable NodeName/NodeID
- **Distributed lock package** — Valkey-based `SET NX EX` + Lua safe unlock; in-process fallback
- **Cross-node cache coordination** — stampede prevention, stale-revalidate, rate-limit counters
- **Rate limit fail-close** — on Valkey error, fail closed (SERVFAIL all) vs fail open (allow all)

## Roadmap

See [Plan.md](./Plan.md) for short-term and long-term goals.

## Quick Start

```shell
docker compose up northstar-dev
dig @localhost -p 8053 example.com
```

For production:

```shell
docker compose up northstar
```

> Port 8053 is the default. Set `NORTHSTAR_DNS_PORT=53` and add `cap_add: NET_BIND_SERVICE` to the compose service for privileged port binding.

## Configuration

NorthStar supports two configuration sources with a clear override hierarchy:

```
built-in defaults  <  YAML config file  <  environment variables
```

**Environment variables always win** — if a restart with different env vars should override a config file value, just set the env var.

### Config file

On first startup, the server auto-generates a default `northstar.yaml` with all settings and explanatory comments. You can edit this file and the server will pick it up on restart (or on `SIGHUP`).

To use a custom path, set `NORTHSTAR_CONFIG`:

```shell
export NORTHSTAR_CONFIG=/etc/northstar/config.yaml
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `NORTHSTAR_CONFIG` | `./northstar.yaml` | Path to YAML config file (auto-generated if missing) |
| `NORTHSTAR_MODE` | `prod` | Runtime mode. `dev` enables colored console output |
| `NORTHSTAR_DNS_PORT` | `53` | DNS listener port (UDP and TCP) |
| `NORTHSTAR_UPSTREAM` | `8.8.8.8:53` | Upstream resolver address (legacy, use `upstreams` in YAML) |
| `NORTHSTAR_CACHE_ADDR` | _(empty)_ | Valkey address (`host:port`). Empty uses in-memory cache |
| `NORTHSTAR_CACHE_FILE` | _(empty)_ | Path to bbolt cache file for on-disk storage |
| `NORTHSTAR_DNS_CACHE_WARMUP` | `false` | Warm cache from Valkey/bbolt on startup |
| `NORTHSTAR_DNS_IPV4_DISABLE` | `false` | Disable IPv4 listener |
| `NORTHSTAR_DNS_IPV6_DISABLE` | `false` | Disable IPv6 listener (default: dual-stack `::`) |
| `NORTHSTAR_TCP_DISABLE` | `false` | Disable TCP listener |
| `NORTHSTAR_DNS_RATE_LIMIT` | `0` | Max queries/second per client. `0` disables rate limiting |
| `NORTHSTAR_DNS_STALE_AGE` | `60` | Seconds to serve stale entries while refreshing in background |
| `NORTHSTAR_DNS_NEGATIVE_TTL` | `60` | TTL for negative cache entries (NXDOMAIN/NODATA) |
| `NORTHSTAR_DNS_TTL_MIN` | `0` | Minimum TTL override (0 = no override) |
| `NORTHSTAR_DNS_TTL_MAX` | `0` | Maximum TTL override (0 = no override) |
| `NORTHSTAR_DNS_CACHE_MAX_ENTRIES` | `10000` | Max cache entries before LRU eviction |
| `NORTHSTAR_MAX_TCP_CONNS_PER_CLIENT` | `0` | Max concurrent TCP connections per client IP (0 = unlimited) |
| `NORTHSTAR_UPSTREAM_POOL_SIZE` | `10` | Max idle upstream connections per pool (UDP + TCP separate) |
| `NORTHSTAR_UPSTREAM_POOL_IDLE` | `30` | Seconds before an idle upstream connection is closed |
| `NORTHSTAR_UPSTREAM_CONCURRENCY` | `3` | Max upstreams to query in parallel |
| `NORTHSTAR_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `NORTHSTAR_LOG_MODE` | _(matches MODE)_ | Log mode override. `dev` adds color to console output |
| `NORTHSTAR_LOG_DIR` | `.` | Log file output directory |
| `NORTHSTAR_LOG_RETENTION` | `7` | Days to retain log files |
| `NORTHSTAR_TZ` | _(empty)_ | Timezone (e.g. `Europe/Berlin`) |
| `NORTHSTAR_METRICS_ENABLE` | `false` | Enable Prometheus metrics endpoint |
| `NORTHSTAR_METRICS_PORT` | `9153` | Metrics HTTP server port |
| `NORTHSTAR_DEBUG_ENABLE` | `false` | Enable pprof debug endpoints |
| `NORTHSTAR_TLS_CERT_FILE` | _(auto)_ | TLS certificate file path |
| `NORTHSTAR_TLS_KEY_FILE` | _(auto)_ | TLS key file path |
| `NORTHSTAR_TLS_CA_FILE` | _(empty)_ | TLS CA file for mutual TLS |
| `NORTHSTAR_TLS_AUTO_SELF_SIGNED` | `true` | Auto-generate self-signed cert if missing |
| `NORTHSTAR_DOT_ENABLED` | `true` | Enable DNS-over-TLS listener |
| `NORTHSTAR_DOT_PORT` | `853` | DoT listener port |
| `NORTHSTAR_DOH_ENABLED` | `true` | Enable DNS-over-HTTPS listener |
| `NORTHSTAR_DOH_PORT` | `443` | DoH listener port |
| `NORTHSTAR_DOQ_ENABLED` | `true` | Enable DNS-over-QUIC listener |
| `NORTHSTAR_DOQ_PORT` | `853` | DoQ listener port |
| `NORTHSTAR_DNS64_PREFIX` | `64:ff9b::/96` | NAT64 prefix for DNS64 synthesis |
| `NORTHSTAR_ECS_PREFIX_V4` | `24` | Source prefix length for IPv4 ECS |
| `NORTHSTAR_ECS_PREFIX_V6` | `56` | Source prefix length for IPv6 ECS |
| `NORTHSTAR_API_ENABLE` | `false` | Enable REST API |
| `NORTHSTAR_API_PORT` | `9163` | REST API port |
| `NORTHSTAR_API_KEY` | _(empty)_ | API authentication key |
| `NORTHSTAR_REUSE_PORT` | `false` | Enable SO_REUSEPORT for multi-worker listeners |
| `NORTHSTAR_REUSE_PORT_WORKERS` | `0` | Number of REUSEPORT worker goroutines (0 = auto) |
| `NORTHSTAR_RATE_LIMIT_FAIL_CLOSE` | `false` | Fail closed (SERVFAIL) on rate-limit backend error |
| `NORTHSTAR_NODE_NAME` | _(hostname)_ | Human-readable node name |
| `NORTHSTAR_NODE_ID` | _(hostname)_ | Node identifier |
| `NORTHSTAR_TRACING_ENABLE` | `false` | Enable OpenTelemetry tracing |
| `NORTHSTAR_TRACING_ENDPOINT` | `localhost:4317` | OTLP gRPC endpoint |
| `NORTHSTAR_TRACING_SAMPLE_RATE` | `0.1` | Trace sample rate (0.0–1.0) |

## REST API

When `api_enable: true`, northstar exposes a REST API on port 9163.

### Authentication

Set `api_key` in config. Clients provide it via `X-API-Key` header or `?api_key=` query parameter. The `/api/v1/health` endpoint is unauthenticated.

### Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Health check (no auth) |
| `GET` | `/api/v1/status` | Full system status |
| `GET` | `/api/v1/config` | Current config (API key masked) |
| `GET` | `/api/v1/upstreams` | List upstream resolvers |
| `GET` | `/api/v1/upstreams/{name}` | Get upstream details |
| `POST` | `/api/v1/upstreams` | Create upstream |
| `PUT` | `/api/v1/upstreams/{name}` | Update upstream |
| `DELETE` | `/api/v1/upstreams/{name}` | Delete upstream |
| `GET` | `/api/v1/cache` | Cache stats |
| `DELETE` | `/api/v1/cache` | Flush cache |
| `DELETE` | `/api/v1/cache/{domain}` | Delete domain entries |
| `DELETE` | `/api/v1/cache/{domain}/{qtype}` | Delete specific entry |
| `GET` | `/api/v1/cache/{domain}/{qtype}` | Inspect cache entry |
| `GET` | `/api/v1/filter/blocklists` | List blocklist paths + counts |
| `GET` | `/api/v1/filter/allowlists` | List allowlist paths + counts |
| `POST` | `/api/v1/filter/reload` | Reload filter files |
| `POST` | `/api/v1/filter/test` | Test if domain is blocked |
| `GET` | `/api/v1/filter/stats` | Filter statistics |
| `GET` | `/api/v1/zones` | List authoritative zones |
| `GET` | `/api/v1/zones/{name}` | Get zone config |
| `POST` | `/api/v1/zones` | Create zone |
| `PUT` | `/api/v1/zones/{name}` | Update zone |
| `DELETE` | `/api/v1/zones/{name}` | Delete zone |
| `POST` | `/api/v1/zones/{name}/reload` | Reload zone from config |
| `GET` | `/api/v1/acls` | List ACL rules |
| `GET` | `/api/v1/acls/{name}` | Get ACL rule |
| `POST` | `/api/v1/acls` | Create ACL rule |
| `PUT` | `/api/v1/acls/{name}` | Update ACL rule |
| `DELETE` | `/api/v1/acls/{name}` | Delete ACL rule |
| `POST` | `/api/v1/reload` | Reload config (SIGHUP equivalent) |

## Monitoring & Observability

### Metrics

Set `metrics_enable: true` in the config (default port `9153`) to expose a `/metrics` endpoint.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `northstar_dns_queries_total` | Counter | `qtype` | Total DNS queries received |
| `northstar_dns_errors_total` | Counter | `type` | Errors by category (parse_error, servfail, rate_limited) |
| `northstar_dns_active_handlers` | Gauge | — | Current in-flight request handlers |
| `northstar_cache_lookups_total` | Counter | — | Total cache lookups |
| `northstar_cache_hits_total` | Counter | — | Fresh cache hits |
| `northstar_cache_negative_lookups_total` | Counter | — | Negative cache lookups |
| `northstar_cache_negative_hits_total` | Counter | — | Negative cache hits (NXDOMAIN/NODATA) |
| `northstar_cache_evictions_total` | Counter | `backend` | Evictions by backend (memory, valkey, bbolt) |
| `northstar_upstream_latency_seconds` | Histogram | `name` | Upstream query latency |
| `northstar_upstream_probe_duration_seconds` | Histogram | `name` | Health probe duration |
| `northstar_upstream_healthy` | Gauge | `name` | Upstream health status (1=healthy) |
| `northstar_upstream_queries_total` | Counter | `name` | Queries sent per upstream |
| `northstar_upstream_fails_total` | Counter | `name` | Upstream failures |
| `northstar_upstream_conditional_hits_total` | Counter | `name, pattern` | Conditional route matches |
| `northstar_filter_blocked_total` | Counter | `action, qtype` | Blocked queries |
| `northstar_dnssec_validation_status_total` | Counter | `status` | DNSSEC validation results |
| `northstar_dns64_syntheses_total` | Counter | — | AAAA record syntheses |
| `northstar_ecs_queries_total` | Counter | `family` | ECS-injected queries |
| `northstar_zone_queries_total` | Counter | `zone, qtype` | Authoritative zone queries |

A pre-built Grafana dashboard is available at [`grafana/dashboard.json`](grafana/dashboard.json). Example Prometheus scrape config at [`prometheus.yml`](prometheus.yml).

### pprof Debug Endpoints

Set `debug_enable: true` in the config to mount Go runtime profiling endpoints on the metrics HTTP server:

- `/debug/pprof/` — profiling index
- `/debug/pprof/profile` — CPU profile
- `/debug/pprof/heap` — heap profile
- `/debug/pprof/goroutine` — goroutine dump
- `/debug/pprof/trace` — execution trace

Usage:
```shell
go tool pprof http://localhost:9153/debug/pprof/profile
```

### OpenTelemetry Tracing

Configure tracing in YAML:

```yaml
tracing:
  enable: true
  endpoint: otel-collector:4317
  service_name: northstar
  sample_rate: 0.1
```

Produces spans at four lifecycle points:
- `dns.query` — entire query lifecycle
- `dns.resolve` — cache lookup + upstream fetch
- `dns.upstream_query` — individual upstream query
- `dns.hook.<name>` — per-hook execution

### Query Log

Enable the query log via `hooks > query_log` in the config:

```yaml
hooks:
  query_log:
    enabled: true
    priority: 900
    file: ./query.log
    retention_days: 7
```

Produces daily-rotated CSV files (`query-YYYY-MM-DD.log`) with fields: timestamp, client IP, query name, query type, RCODE, latency (ms), cache decision, upstream.

## Configuration Examples

### Blocking

```yaml
hooks:
  blocking:
    enabled: true
    block_action: nxdomain
    blocklists:
      - ./blocklist.txt
    allowlists:
      - ./allowlist.txt
    domain_rps: 0
    rpz:
      - path: ./rpz.txt
        action: nxdomain
```

### Multiple Upstreams with Conditional Forwarding

```yaml
upstreams:
  - name: cloudflare
    address: 1.1.1.1:53
    priority: 1
    health_check: true
    timeout: 5
  - name: internal
    address: 10.0.0.1:53
    priority: 0
    health_check: true

conditional_routes:
  - domain: internal.corp
    upstream: internal
```

### Encrypted Transports

```yaml
tls:
  cert_file: /etc/northstar/cert.pem
  key_file: /etc/northstar/key.pem
  auto_self_signed: true

dot_enabled: true
dot_port: 853
doh_enabled: true
doh_port: 443
doq_enabled: true
doq_port: 853
```

### Authoritative Zones with DNSSEC Signing

```yaml
zones:
  - name: example.com
    records:
      - name: "@"
        type: SOA
        ttl: 3600
        mname: ns1.example.com
        rname: admin.example.com
        serial: 2026000001
        refresh: 3600
        retry: 900
        expire: 86400
        minimum: 3600
      - name: "@"
        type: A
        ttl: 300
        ip: 192.0.2.1
      - name: www
        type: CNAME
        ttl: 300
        target: example.com
    dnssec:
      enabled: true
      algorithm: ECDSAP256SHA256
```

### Access Control Lists

```yaml
acls:
  - name: block-dnssec
    action: refuse
    subnet: 10.0.0.0/24
    zone: .
  - name: route-internal
    action: route
    subnet: 192.168.0.0/16
    zone: internal.corp
    upstream: internal-dns
  - name: allow-local
    action: allow
    subnet: 127.0.0.0/8
  - name: block-tcp
    action: drop
    protocol: tcp
    subnet: 0.0.0.0/0
```

## Architecture

NorthStar accepts DNS queries on configurable ports over UDP, TCP, TLS, DoH, and DoQ. Each query passes through a hook pipeline before resolution:

```
Client ──► Listener (UDP/TCP/TLS/DoH/DoQ)
                │
                ▼
         Hook Pipeline (PreResolve)
                │
                ├── SpecialDomainHook  (RFC 6761)
                ├── AuthoritativeHook  (local zones)
                ├── AclHook            (access control)
                ├── RateLimitHook      (per-client)
                ├── BlockingHook       (block/allow/RPZ)
                ├── QMinimizerHook     (QNAME min)
                ├── AnyQueryHook       (RFC 8482)
                ├── Dns64Hook          (AAAA synthesis)
                └── EcsHook            (EDNS client subnet)
                │
                ▼
         resolve() ──► Cache Lookup ──► Inflight Dedup ──► Upstream Pool
                │                           │                    │
                ▼                           ▼                    ▼
         Hook Pipeline (PostResolve)   Cache Stampede      Prometheus Metrics
                │                      Prevention          + OTel Tracing
                ▼
         DnssecHook (RRSIG validation)
                │
                ▼
         Build Response ──► Hook Pipeline (PreResponse)
                │
                ▼
         Hook Pipeline (PostResponse)
                │
                ├── QueryLogHook (CSV logging)
                │
                ▼
              Client
```

The cache backend can be in-process memory, bbolt file, or a shared Valkey instance for multi-instance deployments. Metrics and tracing provide full observability.

## Development

```shell
just build     # go build -o northstar
just test      # go test -v ./...
just lint      # golangci-lint run
just check     # fmt + lint + test + build + clean
```

For hot-reload development:

```shell
docker compose up northstar-dev
```

Source changes trigger an automatic rebuild and restart inside the container.

## Dependencies

- [godotenv](https://github.com/joho/godotenv) — `.env` file loading
- [valkey-go](https://github.com/valkey-io/valkey-go) — Valkey/Redis-compatible cache client
- [prometheus/client_golang](https://github.com/prometheus/client_golang) — Prometheus metrics
- [bbolt](https://go.etcd.io/bbolt) — file-based cache backend
- [quic-go](https://github.com/quic-go/quic-go) — DNS-over-QUIC transport
- [OpenTelemetry Go SDK](https://go.opentelemetry.io/otel) — distributed tracing

## License

MIT + Commons Clause v1.0. See [LICENSE](LICENSE).

Permitted uses include personal, home, and non-profit operation. The software itself may not be sold or offered as a commercial service without adding significant value.
