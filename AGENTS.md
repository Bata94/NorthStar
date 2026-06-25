# northstar — Agent Context

## Project
`github.com/bata94/northstar` — a learning DNS server in Go (1.26) that forwards queries to an upstream resolver, caches responses, and responds to clients.

## Architecture

```
main.go
  └─ config.Load() → Config{Mode, DNSPort, UpstreamAddr, CacheAddr, Listeners, TcpDisable, RateLimit, StaleAge, UpstreamPoolSize, UpstreamPoolIdle, LogLevel, LogMode, LogDir, LogRetention, TimeZone, MetricsEnable, MetricsPort, ConfigPath, Hooks, NodeName, NodeID, ReusePort, ReusePortWorkers, RateLimitFailClose}
  │    └─ load YAML file (env NORTHSTAR_CONFIG or ./northstar.yaml)
  │    └─ overlay env vars on top (env > file > defaults)
  │    └─ auto-generate default file if missing (main.go pre-flight)
  └─ node.InstanceID() + node.NodeName(cfg.NodeName) → instance identity (startup log, API /status)
  └─ config.NewRuntimeConfig(&cfg) → atomic runtime values for SIGHUP reload
  └─ buildPipeline(&cfg, cache, metrics) → resolver.SetPipeline(p) (atomic swap)
  └─ cache.NewMemory(maxEntries, m) or cache.NewValkey(addr, staleAge, m) or cache.NewBbolt(path, staleAge, m) → cache.Cache (metrics for eviction counters; TryLock/Unlock for cross-node coordination)
  └─ log.New(level, mode) → slog.Logger (consoleHandler + JSON file)
  └─ metrics.New() → *metrics.Metrics (custom prometheus registry)
  └─ if DebugEnable → /debug/pprof/ mounted on metrics HTTP server
  └─ upstream.NewGroup(cfg, m) → *Group (metrics for conditional hits)
  └─ resolver.NewPool(upstream, udp) + resolver.NewPool(upstream, tcp) → *Pool
  └─ signal.NotifyContext → ctx (SIGTERM/SIGINT)
  └─ signal.Notify → sighupCh (SIGHUP → reload config + rebuild pipeline)
  └─ if MetricsEnable → metrics.Serve(ctx, addr, m) (goroutine)
  └─ resolver.Serve(ctx, Listener, upstream, cache, staleAge, pool, m, pipeline)  (× listeners)
  │    └─ if !TcpDisable → resolver.ServeTCP(ctx, Listener, upstream, cache, staleAge, pool, m, pipeline)
  │
  ├─ Serve: UDP read loop (1s deadline for ctx polling)
  │    └─ go handleRequest(ctx, data, remoteAddr, conn, upstream, cache, staleAge, pool, m, pipeline)
  │         └─ processQuery(ctx, req, network, clientIP, maxPayload, do, send, upstream, cache, staleAge, pool, m, pipeline)
  │              ├─ m.QueriesTotal (by qtype)
  │              ├─ pipeline.Run(PreResolve, hookCtx) → rate limiting via hook
  │              │    └─ RateLimitHook: cache.Incr(key, 1s) → SERVFAIL if exceeded
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
  │              ├─ pipeline.Run(PostResolve, hookCtx)  (noop in Phase 1)
  │              ├─ entry.CopyRecordsWithAdjustedTTL() → build response
  │              ├─ pipeline.Run(PreResponse, hookCtx)  (noop in Phase 1)
  │              ├─ if len(packed) > maxPayload → set TC bit, truncate
  │              ├─ send(respPacked)
  │              └─ pipeline.Run(PostResponse, hookCtx)  (noop in Phase 1)
  │
  └─ ServeTCP: TCP accept loop (1s deadline)
       └─ go handleTCPConnection(ctx, conn, upstream, cache, staleAge, pool, m, pipeline)
            └─ processQuery(...) (same flow as UDP)
```

## Packages

### `config`
- Structs: `Config` (17 fields), `Listener`, `HookConfig`, `RateLimitHookConfig`
- `Load()` reads `.env` (godotenv, no-overwrite) + YAML file + env vars
- Override hierarchy: defaults < YAML file < environment variables
- Env keys: `NORTHSTAR_MODE`, `NORTHSTAR_DNS_PORT`, `NORTHSTAR_UPSTREAM`, `NORTHSTAR_CACHE_ADDR`, `NORTHSTAR_DNS_IPV4_DISABLE`, `NORTHSTAR_DNS_IPV6_DISABLE`, `NORTHSTAR_TCP_DISABLE`, `NORTHSTAR_DNS_RATE_LIMIT`, `NORTHSTAR_DNS_STALE_AGE`, `NORTHSTAR_UPSTREAM_POOL_SIZE`, `NORTHSTAR_UPSTREAM_POOL_IDLE`, `NORTHSTAR_LOG_LEVEL`, `NORTHSTAR_LOG_MODE`, `NORTHSTAR_LOG_DIR`, `NORTHSTAR_LOG_RETENTION`, `NORTHSTAR_TZ`, `NORTHSTAR_METRICS_ENABLE`, `NORTHSTAR_METRICS_PORT`, `NORTHSTAR_CONFIG`
- `CacheAddr` defaults to `""` (in-memory); set to Valkey address for external cache
- If both v4+v6 enabled → single `::` listener (dual-stack bind)
- If one disabled → separate listeners for the enabled family
- `ConfigPath` — path to YAML file (env `NORTHSTAR_CONFIG`, default `./northstar.yaml`)
- `Load()` auto-generates default YAML file if missing (done in main.go pre-flight)
- `Reload()` — re-reads config file + env vars for SIGHUP hot-reload
- `RuntimeConfig` — atomic values for hot-swappable settings (RateLimit, StaleAge, LogLevel, LogMode)
- `WriteDefaultConfig(path)` — writes a complete YAML file with all defaults and hierarchy explanation header

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

### Log Level Conventions
Default prod level is `warn`, so `Info` and `Debug` are invisible in prod unless explicitly configured.
- **`Error`** — real service degradation: upstream failures, cache backend errors, drain timeouts, cache set failures, SERVFAIL returned to clients, background refresh failures, response truncation (partial data sent). Also syscall/IO failures that prevent operation (deadline, close, write errors).
- **`Warn`** — lifecycle events operators should see in prod: server startup/shutdown, listener addresses, shutdown initiation after error, draining message. Also notable anomalies: rate limit exceeded, malformed client requests, Valkey operational errors.
- **`Info`** — notable operational events visible only when `logLevel=info`: stale-while-revalidate cache behavior, response truncation events, cache backend choice.
- **`Debug`** — high-frequency per-query tracing: cache hit/miss, query completion, inflight dedup waits. Only visible in dev mode.

### `hooks`
- `Lifecycle` enum: `PreResolve`, `PostResolve`, `PreResponse`, `PostResponse`
- `Context` struct carrying request state through the pipeline (`Request`, `Response`, `Entry`, `ClientIP`, `Network`, `Cache`, `Metrics`, `Send`)
- `Hook` interface: `Name()`, `Lifecycle()`, `Priority()`, `Enabled()`, `Handle(*Context) error`
- `Pipeline` — thread-safe sorted slices per lifecycle; `Register()` inserts by priority, `Run()` iterates enabled hooks
- `RateLimitHook` (PreResolve) — replaces the hardcoded rate-limit check; uses `cache.Incr` with second-granularity key; configurable action (`servfail`)
- `QueryLogHook` (PostResponse, prio 900) — CSV per-request log with daily rotation; fields: timestamp, client_ip, qname, qtype, rcode, latency_ms, cache_decision, upstream
- Phase 1: only `RateLimitHook` is wired; other lifecycle points are placeholders

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
- `processQuery` loads the current pipeline via `pipelinePtr.Load()` on each request, ensuring SIGHUP reloads take effect immediately without race conditions
- `Serve` (UDP) / `ServeTCP` — accept loops with 1s deadline for ctx polling, graceful drain (5s timeout)
- SO_REUSEPORT: `listenConfig(reusePort bool)` returns `net.ListenConfig` with `Control` func setting SO_REUSEPORT socket option; uses syscall constants (0x0F on Linux, 0x0200 on Darwin)
- Multiple workers: when `ReusePortWorkers > 1`, main.go spawns N goroutines per listener, each getting its own socket via SO_REUSEPORT; kernel distributes UDP/TCP packets across workers
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
- `Metrics` struct with 16 collectors + custom `prometheus.Registry`
  - `QueriesTotal` — CounterVec by `qtype`
  - `CacheLookups` / `CacheHits` — Counter
  - `CacheEvictionsTotal` — CounterVec by `backend` (memory/valkey/bbolt)
  - `NegativeCacheLookups` / `NegativeCacheHits` — Counter
  - `UpstreamLatency` — HistogramVec by `name` (buckets: 1ms–5s)
  - `UpstreamQueries` / `UpstreamFails` — CounterVec by `name`
  - `UpstreamConditionalHits` — CounterVec by `name`, `pattern`
  - `UpstreamHealthy` — GaugeVec by `name`
  - `UpstreamProbeDuration` — HistogramVec by `name`
  - `ErrorsTotal` — CounterVec by `type` (parse_error, rate_limited, servfail)
  - `ActiveHandlers` — Gauge
  - `BlockedTotal` — CounterVec by `action`, `qtype`
  - `DnssecValidationStatus` — CounterVec by `status`
  - `Dns64SynthesesTotal` — Counter
  - `EcsQueriesTotal` — CounterVec by `family`
  - `ZoneQueriesTotal` — CounterVec by `zone`, `qtype`
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
- Multi-node same-host: set `NORTHSTAR_REUSE_PORT=true`, shared `NORTHSTAR_CACHE_ADDR=valkey:6379`, distinct ports for metrics/API
- Cross-node dedup: uses `cache.TryLock` via Valkey; each node's `inflightCalls` map adds fast local dedup on top

## License
- MIT + Commons Clause v1.0 — see `LICENSE`
- Permits personal, home, and non-profit use
- Prohibits selling the software itself (i.e., distributing or offering it as a service without adding significant value)
