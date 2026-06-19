# northstar — Agent Context

## Project
`github.com/bata94/northstar` — a learning DNS server in Go (1.26) that forwards queries to an upstream resolver, caches responses, and responds to clients.

## Architecture

```
main.go
  └─ config.Load() → Config{Mode, DNSPort, UpstreamAddr, CacheAddr, Listeners, TcpDisable, RateLimit, StaleAge, UpstreamPoolSize, UpstreamPoolIdle, LogLevel, LogMode, MetricsEnable, MetricsPort}
  └─ cache.NewMemory() or cache.NewValkey(addr) → cache.Cache
  └─ log.New(level, mode) → slog.Logger (consoleHandler + JSON file)
  └─ metrics.New() → *metrics.Metrics (custom prometheus registry)
  └─ resolver.NewPool(upstream, udp) + resolver.NewPool(upstream, tcp) → *Pool
  └─ signal.NotifyContext → ctx
  └─ if MetricsEnable → metrics.Serve(ctx, addr, m) (goroutine)
  └─ resolver.Serve(ctx, Listener, upstream, cache, rateLimit, staleAge, pool, m)  (× listeners)
  │    └─ if !TcpDisable → resolver.ServeTCP(ctx, Listener, upstream, cache, rateLimit, staleAge, pool, m)
  │
  ├─ Serve: UDP read loop (1s deadline for ctx polling)
  │    └─ go handleRequest(ctx, data, remoteAddr, conn, upstream, cache, rateLimit, staleAge, pool, m)
  │         ├─ m.ActiveHandlers inc/dec
  │         ├─ dns.Message.Parse() → Question{Name, Type, Class}
  │         ├─ guard len(req.Questions) == 0 → silent drop
  │         ├─ m.QueriesTotal (by qtype)
  │         ├─ if rateLimit > 0 → cache.Incr(key, 1s) → SERVFAIL if exceeded
  │         ├─ resolve(ctx, Name, Type, upstream, cache, maxPayload, network, staleAge, pool, do, m)
  │         │    ├─ m.CacheLookups.Inc()
  │         │    ├─ cache.Peek(ctx, domain, qtype) → fresh hit → m.CacheHits.Inc(), return
  │         │    ├─ stale-while-revalidate: if staleAge > 0 && stale.Peek → refreshCache() goroutine, return stale
  │         │    ├─ inflight dedup: inflightKey{domain,qtype} → wait or become leader
  │         │    │   └─ on failed inflight call → delete from map, fall through to direct fetch
  │         │    └─ fetchFromUpstream(ctx, domain, qtype, maxPayload, network, pool, do, m)
  │         │         ├─ abort goroutine: close upstream conn on ctx.Done()
  │         │         ├─ m.UpstreamLatency.Observe() (deferred)
  │         │         ├─ pool.Acquire(ctx) → net.Conn (reuse or Dial)
  │         │         ├─ SetWriteDeadline(10s) on upstream write
  │         │         ├─ OPT record with DO bit (0x00008000) → upstream AD bit in entry
  │         │         ├─ forward query (UDP raw or TCP length-prefixed)
  │         │         ├─ parse upstream reply → cache.NewEntry(...)
  │         │         ├─ pool.Release(conn, nil)
  │         │         ├─ entry.Flags = upstream header (preserves AA/RA/TC)
  │         │         ├─ entry.RCode = upstream flags & 0x000F
  │         │         └─ entry.AuthenticData = upstream flags & 0x0020
  │         ├─ entry.CopyRecordsWithAdjustedTTL() (floors at 1s)
  │         ├─ build response with OPT addition, AD bit in flags
  │         ├─ if len(packed) > maxPayload → set TC bit, truncate
  │         └─ conn.WriteToUDP(packed, remoteAddr)
  │
  └─ ServeTCP: TCP accept loop (1s deadline)
       └─ go handleTCPConnection(ctx, conn, upstream, cache, rateLimit, staleAge, pool, m)
            ├─ abort goroutine: close client conn on ctx.Done()
            ├─ SetReadDeadline(10s), SetWriteDeadline(10s) on client conn
            ├─ 2-byte length prefix + message body (io.ReadFull)
            ├─ guard len(req.Questions) == 0 → silent drop
            ├─ (same resolve/fetch flow as UDP)
            └─ writeTCPResponse(conn, packed) with SetWriteDeadline(10s)
                 └─ 2-byte length prefix + response data
```

## Packages

### `config`
- Structs: `Config` (17 fields), `Listener`
- `Load()` reads `.env` (godotenv, no-overwrite) + env vars
- Env keys: `NORTHSTAR_MODE`, `NORTHSTAR_DNS_PORT`, `NORTHSTAR_UPSTREAM`, `NORTHSTAR_CACHE_ADDR`, `NORTHSTAR_DNS_IPV4_DISABLE`, `NORTHSTAR_DNS_IPV6_DISABLE`, `NORTHSTAR_TCP_DISABLE`, `NORTHSTAR_DNS_RATE_LIMIT`, `NORTHSTAR_DNS_STALE_AGE`, `NORTHSTAR_UPSTREAM_POOL_SIZE`, `NORTHSTAR_UPSTREAM_POOL_IDLE`, `NORTHSTAR_LOG_LEVEL`, `NORTHSTAR_LOG_MODE`, `NORTHSTAR_METRICS_ENABLE`, `NORTHSTAR_METRICS_PORT`
- `CacheAddr` defaults to `""` (in-memory); set to Valkey address for external cache
- If both v4+v6 enabled → single `::` listener (dual-stack bind)
- If one disabled → separate listeners for the enabled family

### `dns`
- Wire-format types: `Header`, `Question`, `ResourceRecord`, `Message`
- `Message.Parse(data)` — decodes with compression, fresh `visited` map per name read (NOT shared across names — caused "compression loop" bug)
- `Message.Pack()` — encodes with name compression via suffix map
- `ResourceRecord.A()` / `AAAA()` — typed accessors
- `readName` / `writeName` — unexported label helpers

### `cache`
- `Cache` interface: `Get(ctx, domain, qtype)`, `Peek(ctx, domain, qtype)`, `Set(ctx, entry)`, `Incr(ctx, key, ttl)`, `Close()`
- Two backends: `Memory` (in-memory, `sync.RWMutex`-protected) and `Valkey` (Valkey/Redis-compatible, via `valkey-go`)
- Keyed by `(domain, qtype)` — each query type cached independently
- `NewEntry(domain, qtype, answers, auth, addl)` — computes expiry from min TTL across records matching `qtype` (answers), falling back to SOA TTL from authorities/additionals; default 3600s if all zero or unmatched
- `Entry.Expired()` — `time.Now().After(ExpiresAt)`
- `Entry.CopyRecordsWithAdjustedTTL()` — deep copies with remaining TTL (floors at 1s, avoids mutating cache on concurrent reads)
- `Entry.RCode` — reflects upstream response RCODE (0=NOERROR, 3=NXDOMAIN, etc.)
- `Entry.AuthenticData` — AD bit from upstream
- `Entry.Flags` — full upstream header flags (preserves AA, RA, TC)
- `Incr()` — rate limiter counter with configurable TTL, protected by `countersMu`
- Valkey backend: raw `dns.Message.Pack()` wire bytes as value, native key TTL, `valkey.IsValkeyNil` for cache misses, graceful fallback on errors
- `Memory` has eviction goroutine (5min ticker) removing expired entries and expired rate-limit counters

### `log`
- Custom `consoleHandler` — colored output in dev mode (DBG=cyan, INF=green, WRN=yellow, ERR=red), plain in prod
- `multiHandler` — writes to both console (colored) and `northstar.log` (JSON)
- `New(levelStr, mode)` — creates `slog.Logger`; level from config (`NORTHSTAR_LOG_LEVEL`), log-to-`northstar.log` file always tried

### `resolver`
- No globals except `inflightCalls` map (package-level, shared across listeners)
- `Serve` (UDP) / `ServeTCP` — accept loops with 1s deadline for ctx polling, graceful drain (5s timeout)
- `inflightKey{domain, qtype}` / `inflightCall{done, entry, err, once}` — dedup concurrent queries for same domain+qtype; secondary callers wait on `call.done`
- `refreshCache()` — background goroutine for stale-while-revalidate; fetches from upstream, updates cache, closes `call.done`, deletes from `inflightCalls`
- `fetchFromUpstream()` — acquires connection from pool, forwards query (UDP raw or TCP length-prefixed), parses reply, releases connection; measures latency with deferred `m.UpstreamLatency.Observe()`
- `clientEDNS()` — parses OPT record (type 41) from additionals for client payload size and DO bit
- `stripOPT()` — removes OPT record before caching
- On upstream error → SERVFAIL (RCODE 2), never caches failures
- Rate limiting via `cache.Incr()` before `resolve()`; returns SERVFAIL with TC=0
- Response truncation (TC bit) when packed message exceeds `maxPayload`
- Workers spawned via `go handleRequest(...)` / `go handleTCPConnection(...)`
- `writeTCPResponse()` — 2-byte length prefix + data
- TCP client reads: `SetReadDeadline(10s)`, goroutine closes conn on `ctx.Done()`
- TCP client writes: `SetWriteDeadline(10s)` in `writeTCPResponse()`
- Upstream writes: `SetWriteDeadline(10s)`, goroutine closes conn on `ctx.Done()`
- Failed inflight calls (e.g., stale background refresh failure) → removed from map, fall through to direct upstream fetch

### `resolver/pool`
- `Pool` struct — `[]idleConn` slice, `sync.Mutex`, max idle count, idle timeout
- `Acquire(ctx)` — pops from idle or `DialContext`
- `Release(conn, err)` — returns to pool on nil err, closes on error or if pool full/closed
- `sweeper()` — goroutine ticks at `idleTO / 2`, evicts stale idle connections
- Two pool instances created in `main.go` (UDP and TCP)

### `metrics`
- `Metrics` struct with 6 collectors + custom `prometheus.Registry`
  - `QueriesTotal` — CounterVec by `qtype`
  - `CacheLookups` / `CacheHits` — Counter
  - `UpstreamLatency` — Histogram (buckets: 1ms–5s)
  - `ErrorsTotal` — CounterVec by `type` (parse_error, rate_limited, servfail)
  - `ActiveHandlers` — Gauge
- `New()` — creates registry and registers all collectors (avoids default registry for test safety)
- `Handler()` — `promhttp.HandlerFor(m.Registry, ...)`
- `Serve(ctx, addr, m)` — HTTP server on address, `/metrics` handler, graceful shutdown via ctx

## Dependencies
- `github.com/joho/godotenv` — `.env` loading
- `github.com/valkey-io/valkey-go` — Valkey/Redis-compatible cache backend
- `github.com/prometheus/client_golang/prometheus` — Prometheus metrics
- `github.com/prometheus/client_golang/prometheus/promhttp` — HTTP handler for metrics

## Tests
- 6 test files: `cache/`, `config/`, `dns/`, `log/`, `metrics/`, `resolver/`
- Run: `just test`
- Lint: `just lint`

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

For commits use commly used conventions and prefix commit messages with `feat:`, `fix:`, `docs:`, `style:`, `refactor:`, `test:`, or `chore:`.

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

## License
- MIT + Commons Clause v1.0 — see `LICENSE`
- Permits personal, home, and non-profit use
- Prohibits selling the software itself (i.e., distributing or offering it as a service without adding significant value)
