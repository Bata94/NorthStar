package resolver

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/internal/testutil"
)

func TestBlastConcurrent(t *testing.T) {
	m := testutil.NewMetrics()
	c := cache.NewMemory(10000, nil)
	defer c.Close()

	var upstreamCalls atomic.Int64
	mock := testutil.StartMockUpstream(t, "udp", func(data []byte) []byte {
		upstreamCalls.Add(1)
		time.Sleep(1 * time.Millisecond)
		var req dns.Message
		if err := req.Parse(data); err != nil {
			return testutil.BuildNXDOMAINResponse("unknown.", 1)
		}
		q := req.Question()
		return testutil.BuildDNSResponse(q, 1, net.ParseIP("1.2.3.4").To4())
	})
	defer mock.Close()

	g := testutil.NewTestGroup(t, mock.AddrStr())
	defer g.Close()

	rc := testutil.NewRuntimeConfig()
	ctx := context.Background()

	domains := []string{
		"alpha.com.", "beta.com.", "gamma.com.", "delta.com.", "epsilon.com.",
		"zeta.com.", "eta.com.", "theta.com.", "iota.com.", "kappa.com.",
		"lambda.com.", "mu.com.", "nu.com.", "xi.com.", "omicron.com.",
		"pi.com.", "rho.com.", "sigma.com.", "tau.com.", "upsilon.com.",
		"phi.com.", "chi.com.", "psi.com.", "omega.com.", "example.com.",
		"test.com.", "demo.com.", "hello.com.", "world.com.", "dns.com.",
		"cache.com.", "miss.com.", "blast.com.", "stress.com.", "load.com.",
		"perf.com.", "bench.com.", "scale.com.", "flood.com.", "burst.com.",
		"spike.com.", "surge.com.", "wave.com.", "tide.com.", "flow.com.",
		"stream.com.", "river.com.", "lake.com.", "ocean.com.", "sea.com.",
	}

	for _, d := range domains[:25] {
		entry := cache.NewEntry(d, 1, 0, []dns.ResourceRecord{{
			Name: d, Type: 1, Class: 1, TTL: 300,
			RDLength: 4, RData: net.ParseIP("10.0.0.1").To4(),
		}}, nil, nil, 0, 0, 0)
		_ = c.Set(ctx, entry)
	}

	totalQueries := 1000
	concurrency := 50
	sem := make(chan struct{}, concurrency)

	type result struct {
		duration time.Duration
		success  bool
	}

	results := make(chan result, totalQueries)
	start := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < totalQueries; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			domain := domains[idx%len(domains)]
			qStart := time.Now()
			entry, _, err := resolve(ctx, domain, 1, g, c, 512, "udp", rc, false, m, nil, "")
			dur := time.Since(qStart)

			results <- result{duration: dur, success: err == nil && entry != nil}
		}(i)
	}

	wg.Wait()
	totalDur := time.Since(start)
	close(results)

	var total time.Duration
	var successes, failures int
	var maxDur time.Duration
	var durations []time.Duration

	for r := range results {
		total += r.duration
		if r.success {
			successes++
		} else {
			failures++
		}
		if r.duration > maxDur {
			maxDur = r.duration
		}
		durations = append(durations, r.duration)
	}

	qps := float64(totalQueries) / totalDur.Seconds()
	avgLatency := total / time.Duration(totalQueries)

	sortDurations(durations)
	var p50, p90, p99 time.Duration
	if len(durations) > 0 {
		p50 = durations[len(durations)*50/100]
		p90 = durations[len(durations)*90/100]
		p99 = durations[len(durations)*99/100]
	}

	t.Logf("=== Blast Test Results ===")
	t.Logf("Total queries:  %d", totalQueries)
	t.Logf("Concurrency:    %d", concurrency)
	t.Logf("Cache warm:     25 of %d domains", len(domains))
	t.Logf("Total time:     %v", totalDur)
	t.Logf("QPS:            %.0f", qps)
	t.Logf("Avg latency:    %v", avgLatency)
	t.Logf("P50 latency:    %v", p50)
	t.Logf("P90 latency:    %v", p90)
	t.Logf("P99 latency:    %v", p99)
	t.Logf("Max latency:    %v", maxDur)
	t.Logf("Successes:      %d", successes)
	t.Logf("Failures:       %d", failures)
	t.Logf("Upstream calls: %d", upstreamCalls.Load())
	t.Logf("==========================")

	if failures > totalQueries/100 {
		t.Errorf("Error rate too high: %d/%d (%.1f%%)", failures, totalQueries,
			float64(failures)/float64(totalQueries)*100)
	}
	if upstreamCalls.Load() == 0 {
		t.Error("Expected at least one upstream call")
	}
}

func sortDurations(d []time.Duration) {
	for i := 0; i < len(d); i++ {
		for j := i + 1; j < len(d); j++ {
			if d[j] < d[i] {
				d[i], d[j] = d[j], d[i]
			}
		}
	}
}

func TestBlastStressCache(t *testing.T) {
	m := testutil.NewMetrics()
	c := cache.NewMemory(10000, m)
	defer c.Close()

	var upstreamCount atomic.Int64
	mock := testutil.StartMockUpstream(t, "udp", func(data []byte) []byte {
		upstreamCount.Add(1)
		time.Sleep(5 * time.Millisecond)
		return testutil.BuildDNSResponse("example.com.", 1, net.ParseIP("1.2.3.4").To4())
	})
	defer mock.Close()

	g := testutil.NewTestGroup(t, mock.AddrStr())
	defer g.Close()

	rc := testutil.NewRuntimeConfig()
	ctx := context.Background()

	entry := cache.NewEntry("example.com.", 1, 0, []dns.ResourceRecord{{
		Name: "example.com.", Type: 1, Class: 1, TTL: 300,
		RDLength: 4, RData: net.ParseIP("10.0.0.1").To4(),
	}}, nil, nil, 0, 0, 0)
	_ = c.Set(ctx, entry)

	totalQueries := 500
	var wg sync.WaitGroup
	var errCount atomic.Int64

	for i := 0; i < totalQueries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := resolve(ctx, "example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "")
			if err != nil {
				errCount.Add(1)
			}
		}()
	}

	wg.Wait()

	uc := upstreamCount.Load()
	t.Logf("Cache stress test: %d queries, %d upstream calls (expected 0-1 for cached domain), %d errors",
		totalQueries, uc, errCount.Load())

	if errCount.Load() > 0 {
		t.Errorf("Expected 0 errors, got %d", errCount.Load())
	}
}

func TestBlastInflightDedupStress(t *testing.T) {
	m := testutil.NewMetrics()
	c := cache.NewMemory(10000, nil)
	defer c.Close()

	var upstreamCount atomic.Int64
	mock := testutil.StartMockUpstream(t, "udp", func(data []byte) []byte {
		upstreamCount.Add(1)
		time.Sleep(20 * time.Millisecond)
		return testutil.BuildDNSResponse("example.com.", 1, net.ParseIP("1.2.3.4").To4())
	})
	defer mock.Close()

	g := testutil.NewTestGroup(t, mock.AddrStr())
	defer g.Close()

	rc := testutil.NewRuntimeConfig()
	ctx := context.Background()

	totalQueries := 200
	concurrency := 100
	sem := make(chan struct{}, concurrency)
	var errCount atomic.Int64

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < totalQueries; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			_, _, err := resolve(ctx, "example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "")
			if err != nil {
				errCount.Add(1)
			}
		}()
	}

	wg.Wait()
	totalDur := time.Since(start)

	uc := upstreamCount.Load()
	t.Logf("Inflight dedup stress: %d queries in %v, %d upstream calls, %d errors",
		totalQueries, totalDur, uc, errCount.Load())

	if uc > 5 {
		t.Errorf("Too many upstream calls: %d (expected ~1-2 with inflight dedup)", uc)
	}
	if errCount.Load() > 0 {
		t.Errorf("Expected 0 errors, got %d", errCount.Load())
	}
}
