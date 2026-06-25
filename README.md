# NorthStar

[![Go](https://img.shields.io/badge/Go-1.26.2-blue?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT_+_Commons_Clause-yellow)](#license)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/bata94/northstar/pulls)
[![Go Reference](https://pkg.go.dev/badge/github.com/bata94/northstar.svg)](https://pkg.go.dev/github.com/bata94/northstar)
[![Go Report Card](https://goreportcard.com/badge/github.com/bata94/northstar)](https://goreportcard.com/report/github.com/bata94/northstar)

A lightweight, high-performance recursive DNS forwarder with on-device caching, per-client rate limiting, DNSSEC passthrough, real-time metrics, and a hook-based middleware pipeline. Designed to be an alternative to Technitium, AdGuard Home, or Pi-hole for users who want full visibility and control over their DNS infrastructure.
Plans include a WebUI-driven configuration system, configuration file support, and pure environment-variable operation.
Multi-node support is architected in and will be added in the future.

Disclaimer: This is a prototype. A lot of it is AI-coded as a proof of concept. The goal is to land all features first, then refactor to production quality once the design is validated.
Until v1.0.0 changes are rapid and not checked for backwards-compatibility! Development will be simply done in the main branch. After v1.0.0, I will move to feature branches with stable patch releases and potentially breaking changes in minor/major releases.

Built for Docker, configured via environment variables, and instrumented with Prometheus out of the box.

## Features

- **DNS forwarding** — forwards queries to any upstream resolver over UDP and TCP
- **Response caching** — in-memory or Valkey-backed cache with configurable TTL
- **Stale-while-revalidate** — serves cached responses during background refresh to minimize latency spikes
- **In-flight request deduplication** — concurrent requests for the same domain wait for a single upstream fetch (thundering herd prevention)
- **DNSSEC passthrough** — preserves DO bit from client to upstream and AD bit from upstream to client
- **EDNS0 support** — respects client payload size announcements; truncates with TC bit when necessary
- **Per-client rate limiting** — fixed-window counters, shareable across instances via Valkey
- **Upstream connection pooling** — reusable UDP and TCP connections to reduce socket churn
- **Dual-stack networking** — single IPv6 listener binds both families; IPv4-only and IPv6-only modes available
- **Prometheus metrics** — query volume by type, cache hit ratio, upstream latency histogram, error counters, active handler gauge
- **Structured logging** — colored console output in dev mode, JSON file output for production ingestion
- **Graceful shutdown** — drains in-flight requests up to 5 seconds before exiting
- **Configurable via YAML file or environment variables** — auto-generates a default config file on first startup; env vars always override file values

## Roadmap

See [Plan.md](./Plan.md), for short-term and long-term goals.

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
| `NORTHSTAR_UPSTREAM` | `8.8.8.8:53` | Upstream resolver address |
| `NORTHSTAR_CACHE_ADDR` | _(empty)_ | Valkey address (`host:port`). Empty uses in-memory cache |
| `NORTHSTAR_DNS_IPV4_DISABLE` | `false` | Disable IPv4 listener |
| `NORTHSTAR_DNS_IPV6_DISABLE` | `false` | Disable IPv6 listener (default: dual-stack `::`) |
| `NORTHSTAR_TCP_DISABLE` | `false` | Disable TCP listener |
| `NORTHSTAR_DNS_RATE_LIMIT` | `0` | Max queries/second per client. `0` disables rate limiting |
| `NORTHSTAR_DNS_STALE_AGE` | `60` | Seconds to serve stale entries while refreshing in background |
| `NORTHSTAR_UPSTREAM_POOL_SIZE` | `10` | Max idle upstream connections per pool (UDP + TCP separate) |
| `NORTHSTAR_UPSTREAM_POOL_IDLE` | `30` | Seconds before an idle upstream connection is closed |
| `NORTHSTAR_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `NORTHSTAR_LOG_MODE` | _(matches MODE)_ | Log mode override. `dev` adds color to console output |
| `NORTHSTAR_LOG_DIR` | `.` | Log file output directory |
| `NORTHSTAR_LOG_RETENTION` | `7` | Days to retain log files |
| `NORTHSTAR_TZ` | _(empty)_ | Timezone (e.g. `Europe/Berlin`) |
| `NORTHSTAR_METRICS_ENABLE` | `false` | Enable Prometheus metrics endpoint |
| `NORTHSTAR_METRICS_PORT` | `9153` | Metrics HTTP server port |

## Monitoring & Observability

northstar exposes Prometheus metrics and optional pprof debug endpoints for observability.

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

## Architecture

NorthStar accepts DNS queries on a configurable port over UDP and TCP. Each query is checked against the cache; on a miss, it is forwarded to the upstream resolver via a pooled connection. Responses are cached with their original TTL plus a stale-age grace window for background revalidation. Concurrent identical queries are deduplicated at the inflight layer — only one goroutine fetches from upstream while others wait on the result.

```
Client ──► UDP/TCP Listener ──► Cache Lookup ──► Inflight Dedup ──► Upstream Pool ──► Resolver
                                    │                                    │
                                    ▼                                    ▼
                              Cache Hit (or stale)                 Prometheus Metrics
```

The cache backend can be either in-process memory (default) or a shared Valkey instance for multi-instance deployments. Metrics are exposed via a separate HTTP server on `/metrics` for Prometheus scraping.

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

## Reverse Proxy

Run northstar behind a TLS-terminating reverse proxy (Caddy, Traefik, nginx) for encrypted client connections without configuring TLS in northstar itself.

### Caddy

```caddyfile
dns.example.com {
    tls your@email.com
    reverse_proxy 127.0.0.1:8053 {
        transport http {
            dial_timeout 5s
            response_header_timeout 30s
        }
    }
}
```

For DNS-over-TLS:
```caddyfile
dot.example.com:853 {
    tls your@email.com
    reverse_proxy 127.0.0.1:8053
}
```

### nginx (stream)

```nginx
stream {
    server {
        listen 853 ssl;
        proxy_pass 127.0.0.1:8053;
        ssl_certificate /etc/certs/cert.pem;
        ssl_certificate_key /etc/certs/key.pem;
    }
}
```

Note: northstar runs with `NET_BIND_SERVICE` capability inside Docker for ports below 1024.

## Dependencies

- [godotenv](https://github.com/joho/godotenv) — `.env` file loading
- [valkey-go](https://github.com/valkey-io/valkey-go) — Valkey/Redis-compatible cache client
- [prometheus/client_golang](https://github.com/prometheus/client_golang) — Prometheus metrics

## License

MIT + Commons Clause v1.0. See [LICENSE](LICENSE).

Permitted uses include personal, home, and non-profit operation. The software itself may not be sold or offered as a commercial service without adding significant value.
