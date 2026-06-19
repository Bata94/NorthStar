# northstar — Roadmap

## Transport Security
- DNS-over-HTTPS (DoH)
- DNS-over-TLS (DoT)
- DNS-over-QUIC (DoQ)

- QNAME Minimization

## Upstream Management
- Concurrent DNS Forwarding
- Upstream Priorities
- Health checking with automatic failover
- Conditional forwarding (route `*.internal.corp` → private resolver)
- Adaptive timeouts per upstream

## Blocking & Filtering
- Blocklists (file-based, one domain per line, `*.wildcard` support)
- Allowlists (takes precedence over blocklists)
- Configurable block action (NXDOMAIN / 0.0.0.0 sinkhole / REFUSED)
- Hot-reload on file changes

## Low RAM Mode
- File-based cache backend (bbolt) — on-disk storage, minimal memory
- Config: `NORTHSTAR_CACHE_FILE` to enable, falls back to current logic when unset
- Periodic expiry compaction

## Configuration
- WebUI
- YAML/TOML config file with env var override hierarchy
- Hot-reload on SIGHUP
- API-first design (WebUI consumes local HTTP API)

## Networking
- DNS Zones (authoritative)
- ACL
- Split-horizon DNS

## Observability
- Revisit metrics pkg, add more and more detailed metrics
- OpenTelemetry tracing
- Tailored Grafana dashboard
- Rotatable query log (who asked for what, latency, cache decision)

## Scaling
- Proper Multinode Support
- Cache warming on startup (reload from Valkey/file)
- Adaptive prefetch for popular entries
