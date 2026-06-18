# NorthStar

[![Go](https://img.shields.io/badge/Go-1.26.2-blue?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT_+_Commons_Clause-yellow)](#license)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/bata94/northstar/pulls)
[![Go Reference](https://pkg.go.dev/badge/github.com/bata94/northstar.svg)](https://pkg.go.dev/github.com/bata94/northstar)
[![Go Report Card](https://goreportcard.com/badge/github.com/bata94/northstar)](https://goreportcard.com/report/github.com/bata94/northstar)

A lightweight, high-performance recursive DNS forwarder with on-device caching, per-client rate limiting, DNSSEC passthrough, and real-time metrics. Designed to be an alternative to Technitium, AdGuard Home, or Pi-hole for users who want full visibility and control over their DNS infrastructure.

Diclaimer: This is a prototype. Alot is AI coded as a proof of concept. I want to get all features in and then I will refactor it to production ready, if it works as intended.

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
- **Configurable via environment variables** — no config files needed

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

All configuration is through environment variables (or a `.env` file in the project root).

| Variable | Default | Description |
|---|---|---|
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
| `NORTHSTAR_METRICS_ENABLE` | `false` | Enable Prometheus metrics endpoint |
| `NORTHSTAR_METRICS_PORT` | `9153` | Metrics HTTP server port |

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

## Dependencies

- [godotenv](https://github.com/joho/godotenv) — `.env` file loading
- [valkey-go](https://github.com/valkey-io/valkey-go) — Valkey/Redis-compatible cache client
- [prometheus/client_golang](https://github.com/prometheus/client_golang) — Prometheus metrics

## License

MIT + Commons Clause v1.0. See [LICENSE](LICENSE).

Permitted uses include personal, home, and non-profit operation. The software itself may not be sold or offered as a commercial service without adding significant value.
