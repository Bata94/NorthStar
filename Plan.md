# northstar — Roadmap

## Priority 1 — Fix 512B Buffer Truncation

**Problem:** `make([]byte, 512)` silently drops data >512B without setting the TC bit. Clients trust the truncated response.

- [x] Client read buffer increased to 1500 bytes (`resolver/resolver.go`)
- [x] Upstream read buffer increased to 1500 bytes (`resolver/resolver.go`)
- [x] Verified: `dig +bufsize=4096` returns full response, no silent truncation

## Priority 2 — Upstream Read Timeout

**Problem:** `fwd.Read(buf)` blocks forever if upstream is slow/dead. Handler goroutines pile up, never recover.

- [x] `fwd.SetReadDeadline` added with 5s timeout before upstream read
- [x] Timeout error handled: returns SERVFAIL to client, does not cache
- [x] ctx-based shutdown still works (no race between deadline and ctx cancel)

## Priority 3 — Graceful Draining

**Problem:** On SIGTERM/SIGINT, in-flight handler goroutines get killed mid-`WriteToUDP`. Clients see incomplete responses.

- [x] `sync.WaitGroup` added to `Serve()` — local var, no signature change
- [x] `wg.Add(1)` before each `go handleRequest(...)`
- [x] `wg.Done()` deferred via closure wrapping `handleRequest`
- [x] `Serve()` blocks on `wg.Wait()` with 5s timeout after read loop exits
- [x] SIGTERM/SIGINT drains up to 5s, then forces shutdown

## Priority 4 — Memory Cache Eviction

**Problem:** Expired entries accumulate in the Memory backend map forever → unbounded growth.

- [x] Periodic sweep goroutine in `NewMemory()` (5 min ticker, stopped via `Close()`)
- [x] Lazy expiry check in `Get()` — expired entries deleted on access, not returned
- [x] Verified: compiles, lints, and runs clean

## Priority 5 — EDNS0 Client Parsing + Payload Size

**Problem:** Server appends a hardcoded OPT record but never reads the client's OPT record. Upstream OPT records can leak into the response (double OPT).

- [x] Client OPT record parsed: scan `Additionals` for Type 41
- [x] UDP payload size extracted from `Class` field
- [x] Upstream buffer size respects client's max payload (cap at 4096, min 512)
- [x] Upstream OPT record stripped before caching (avoid stale OPT in cache)
- [x] Single OPT record in response (ours only, not a duplicate)
- [x] Verified: `dig +bufsize=4096` → response `udp: 4096`; `dig +bufsize=512` → `udp: 512`

## Priority 6 — Context-Aware Timeouts

**Problem:** `ctx` flows from `main`→`Serve`→`resolve` but is never used for I/O deadlines or dial cancellation.

- [x] Upstream dial uses `Dialer.DialContext(ctx, ...)` instead of `net.DialUDP`
- [x] Upstream read deadline derived from ctx deadline (or 5s fallback)
- [x] Shutdown cancels in-flight upstream dials (ctx cancel propagates via DialContext)
- [x] Read deadline ensures bounded wait even if ctx has no deadline (5s fallback)

## Priority 7 — Structured Logging

**Problem:** All 16 log calls use raw `fmt.Printf`/`fmt.Println` with no structure or levels. Debug and error messages are indistinguishable. No file output.

- [x] Replace all `fmt.Printf`/`fmt.Println` with `log/slog` using a custom `multiHandler` that fans out to two outputs
- [x] Stdout handler: `slog.NewTextHandler` with nice formatting (source info, color hints)
- [x] File handler: `slog.NewJSONHandler` writing to `northstar.log` (or configurable path)
- [x] Default levels: dev mode = info+, prod mode = warn+ (both outputs follow same level per mode)
- [x] Config: `NORTHSTAR_LOG_LEVEL` (default `"info"`), `NORTHSTAR_LOG_MODE` (default matches `NORTHSTAR_MODE`)
- [x] Route debug lines (cache hits, per-query log) to `slog.Debug`

## Priority 8 — TCP Support

**Problem:** DNS over UDP is limited by payload size. Responses exceeding the client's buffer must set TC bit for client retry over TCP. Zone transfers (AXFR/IXFR) also require TCP.

- [X] Add `net.ListenTCP` on same port, accept loop goroutine
- [X] Parse TCP DNS wire format (2-byte length prefix before message)
- [X] Forward TCP queries upstream via TCP
- [X] Set TC bit in UDP responses that exceed client's announced payload
- [X] Graceful drain for TCP listener goroutines
- [X] Config: `NORTHSTAR_TCP_DISABLE` env var to disable TCP listener

## Priority 9 — Rate Limiting

**Problem:** Open recursive resolver can be used for DNS amplification attacks. No per-client limits. Rate limit counters must be shareable across instances via the cache backend.

- [x] Extend `Cache` interface with `Incr(ctx, key string, ttl time.Duration) (int64, error)` — atomic increment with expiry
- [x] Implement `Incr` in `Memory` backend (in-memory counter map with expiry)
- [x] Implement `Incr` in `Valkey` backend (`INCR` + `EXPIRE` pipeline)
- [x] Fixed-window counter keyed by `northstar:ratelimit:{client_ip}:{unix_sec}`
- [x] Apply rate limit before `resolve()` — exceeded clients get SERVFAIL
- [x] Config: `NORTHSTAR_DNS_RATE_LIMIT` env var (queries/sec/client, default `0` = disabled)

## Priority 10 — Cache Refresh / Thundering Herd

**Problem:** When a popular entry expires, N concurrent requests all miss cache and hit upstream simultaneously, wasting bandwidth and spiking upstream load.

- [x] Dedup in-flight upstream requests per `(domain, qtype)` — only one goroutine fetches
- [x] Singleflight pattern: subsequent callers wait for and reuse the in-flight result
- [x] Stale-while-revalidate — serve stale entry while refreshing in background (config: `NORTHSTAR_DNS_STALE_AGE`)

## Priority 11 — Upstream Connection Pooling

**Problem:** Each query opens a new UDP socket to upstream, adding overhead and wasting file descriptors under load.

- [x] Custom `Pool` type in `resolver/pool.go` with `Acquire()` / `Release()` / sweeper goroutine
- [x] UDP and TCP pools created in `main.go`, threaded through to `fetchFromUpstream`
- [x] `Pool.Acquire()` returns idle conn or dials new one (never blocks)
- [x] `Pool.Release(conn, err)` returns to idle on success, closes on error or overflow
- [x] Background sweeper closes conns idle longer than timeout (tick = timeout/2)
- [x] Config: `NORTHSTAR_UPSTREAM_POOL_SIZE` (default 10), `NORTHSTAR_UPSTREAM_POOL_IDLE` (default 30s)

## Priority 12 — TTL Calculation Refinement

**Problem:** `cache.NewEntry` computes TTL as min across ALL sections (answers, authorities, additionals). A low-TTL SOA in authorities artificially shortens the entire entry's cache lifetime.

- [X] Compute TTL from queried-type records in Answers only (e.g., for A query, min across A records)
- [X] Fall back to defaultTTL if no matching records
- [X] Keep current behavior as fallback for empty-answers entries (NXDOMAIN with SOA)
- [X] Verify with mixed-TTL responses (e.g., CNAME chain + A record with different TTLs)

## Priority 13 — DNSSEC

**Problem:** Server clears AD flag and ignores DO bit. DNSSEC-aware clients can't use this server for validation.

- [x] `clientEDNS()` extracts DO bit (bit 16 of OPT TTL) from client request
- [x] DO bit threaded through `resolve` → `fetchFromUpstream` → OPT record in upstream query
- [x] `Entry.AuthenticData` field stores AD bit from upstream response flags
- [x] Memory and Valkey backends preserve `AuthenticData` (Valkey packs via flags in wire format)
- [x] Response flags preserve OPCODE + RD + CD from client; set QR + RA + RCODE + AD from entry
- [x] Upstream query now always includes OPT record with client's payload size (fixes pre-existing 512B cap on upstream without EDNS0)
- [x] RRSIG/DNSKEY/NSEC records were already preserved (only Type 41 stripped by `stripOPT`)

## Priority 14 — Unit Tests

**Problem:** Zero test coverage (`go test -v ./...` is empty). No safety net for refactoring.

- [x] `dns/message_test.go` — 17 tests: Pack/Parse round-trip for A, AAAA, CNAME, NS, SOA, OPT; name compression, root name, compression loops, truncated packet/name/question/RR; A/AAAA typed accessors, Question(), multiple questions
- [x] `cache/cache_test.go` — 18 tests: NewEntry TTL from matching type, defaultTTL fallback, empty-answers/SOA fallback, mixed-TTL CNAME+A, no-matching-type fallback, zero TTL; Entry expiry, CopyRecordsWithAdjustedTTL; Memory Get/Set/Peek/Incr, Peek with expired, concurrent access, lazy eviction
- [x] `resolver/resolver_test.go` — 12 tests: stripOPT with/without OPT, clientEDNS (no OPT, DO=1, DO=0), resolve cache hit/miss/upstream-error/NXDOMAIN/stale-while-revalidate/inflight-dedup, fetchFromUpstream DNSSEC/TCP
- [x] `resolver/pool_test.go` — 9 tests: Pool Acquire/Release, idle reuse, overflow close, error close, closed returns ErrClosed, Close closes idle, sweeper evicts stale, concurrent, no sweeper when disabled
- [x] `log/log_test.go` — 12 tests: levelFromString all variants, pad helper, consoleHandler level enforcement/format/color/nocolor, multiHandler dispatch, WithAttrs/WithGroup immutability, New dev/prod modes
- [x] `config/config_test.go` — 12 tests: defaults, custom port/upstream, v4-only/v6-only/both-disabled panics, TCP disable, rate limit, stale age, pool config, cache addr, mode, log config, env var precedence
- [x] Bug fix: `resolve()` used `Get()` which deletes expired entries before stale-while-revalidate can `Peek()` them — changed to `Peek()` first
- [x] Bug fix: `fetchFromUpstream()` had `ARCount: 0` but included OPT record — set `ARCount: 1`

## Priority 15 — Prometheus Metrics

**Problem:** No observability into request volume, cache effectiveness, error rates, or latency.

- [x] Create `metrics` package with `Metrics` struct (custom registry, avoids global state) + `Serve()` HTTP server
- [x] Metrics: `queries_total` (counter by qtype), `cache_lookups_total` / `cache_hits_total`, `upstream_latency_seconds` (histogram), `errors_total` (counter by type: parse_error, rate_limited, servfail), `active_handlers` (gauge)
- [x] Instrument: `handleRequest`/`handleTCPConnection` → active handlers ±, queries total, parse errors, rate limited, servfail; `resolve` → cache lookups/hits; `fetchFromUpstream` → upstream latency
- [x] Config: `NORTHSTAR_METRICS_ENABLE` + `NORTHSTAR_METRICS_PORT` (default 9153)
- [x] Test: `metrics/metrics_test.go` — New(), Handler() serves /metrics with collected data, Serve() start/stop lifecycle, Serve() shutdown via context cancel
