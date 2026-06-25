//go:build integration

package resolver

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/internal/testutil"
)

func TestMain(m *testing.M) {
	if err := probeUpstream("9.9.9.9:53"); err != nil {
		fmt.Fprintf(os.Stderr, "upstream 9.9.9.9 unreachable (%v), skipping output comparison tests\n", err)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func probeUpstream(addr string) error {
	conn, err := net.DialTimeout("udp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	query := testutil.BuildDNSQuery("google.com.", 1)
	if _, err := conn.Write(query); err != nil {
		return err
	}
	resp := make([]byte, 1500)
	_, err = conn.Read(resp)
	return err
}

func TestOutputComparison(t *testing.T) {
	upstreams := []string{"9.9.9.9:53", "8.8.8.8:53", "1.1.1.1:53"}

	domains := []struct {
		domain string
		qtype  uint16
	}{
		{"google.com.", 1},
		{"cloudflare.com.", 1},
		{"github.com.", 1},
		{"wikipedia.org.", 1},
		{"mozilla.org.", 1},
		{"reddit.com.", 1},
		{"apple.com.", 1},
		{"microsoft.com.", 1},
		{"amazon.com.", 1},
		{"google.com.", 28},
		{"cloudflare.com.", 28},
		{"github.com.", 28},
		{"wikipedia.org.", 28},
		{"mozilla.org.", 28},
		{"google.com.", 15},
		{"cloudflare.com.", 15},
		{"google.com.", 6},
		{"cloudflare.com.", 6},
		{"dnssec-tools.org.", 1},
		{"isc.org.", 1},
		{"ietf.org.", 1},
		{"this-domain-does-not-exist-in-any-zone.com.", 1},
		{"qwerytiopsadfghjklzxcvbnm.net.", 1},
		{"localhost.", 1},
		{"1.2.3.4.", 1},
		{"10.in-addr.arpa.", 12},
	}

	for _, upstreamAddr := range upstreams {
		t.Run(upstreamAddr, func(t *testing.T) {
			m := testutil.NewMetrics()
			c := cache.NewMemory(0, nil)
			defer c.Close()

			g := testutil.NewTestGroupTargeted(t, []config.UpstreamConfig{{
				Name:        "upstream",
				Address:     upstreamAddr,
				Priority:    0,
				Timeout:     10,
				HealthCheck: false,
				MaxFails:    3,
				Weight:      1,
			}})
			defer g.Close()

			rc := testutil.NewRuntimeConfig()
			ctx := context.Background()

			for _, d := range domains {
				t.Run(d.domain+"_"+fmt.Sprint(d.qtype), func(t *testing.T) {
					directResp, err := testutil.SendUDPQuery(upstreamAddr, testutil.BuildDNSQuery(d.domain, d.qtype))
					if err != nil {
						t.Skipf("Direct query failed: %v", err)
					}
					directMsg := &dns.Message{}
					if err := directMsg.Parse(directResp); err != nil {
						t.Skipf("Direct parse failed: %v", err)
					}

					dCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
					defer cancel()
					entry, _, err := resolve(dCtx, d.domain, d.qtype, g, c, 512, "udp", rc, false, m, nil, "")
					if err != nil {
						t.Errorf("Northstar resolve error: %v", err)
						return
					}
					if entry == nil {
						t.Error("Northstar returned nil entry")
						return
					}

					directRCode := directMsg.Header.Flags & 0x000F
					if entry.RCode != directRCode {
						t.Errorf("RCODE mismatch: northstar=%d, direct=%d", entry.RCode, directRCode)
					}

					nsTypeCount := len(entry.Answers)
					directTypeCount := len(directMsg.Answers)
					if nsTypeCount > 0 && directTypeCount > 0 {
						t.Logf("%s type=%d: northstar=%d answers, direct=%d answers",
							d.domain, d.qtype, nsTypeCount, directTypeCount)

						nsIPs := extractIPs(entry.Answers)
						directIPs := extractIPs(directMsg.Answers)
						common := intersectIPs(nsIPs, directIPs)
						if len(common) == 0 && len(nsIPs) > 0 && len(directIPs) > 0 {
							t.Logf("No overlapping IPs (anycast variance): northstar=%v, direct=%v",
								nsIPs, directIPs)
						}
					} else if nsTypeCount == 0 && directTypeCount > 0 {
						t.Errorf("Northstar returned 0 answers, direct returned %d", directTypeCount)
					}

					if nsTypeCount > 0 && directTypeCount > 0 {
						nsAns := entry.Answers[0]
						dAns := directMsg.Answers[0]
						if nsAns.TTL > 0 && dAns.TTL > 0 {
							ratio := float64(nsAns.TTL) / float64(dAns.TTL)
							if ratio > 2.0 || ratio < 0.1 {
								t.Logf("TTL divergence: northstar=%d, direct=%d (ratio=%.2f)",
									nsAns.TTL, dAns.TTL, ratio)
							}
						}
					}
				})
			}
		})
	}
}

func extractIPs(rrs []dns.ResourceRecord) []string {
	var ips []string
	for _, rr := range rrs {
		if rr.Type == dns.TypeA && len(rr.RData) == 4 {
			ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", rr.RData[0], rr.RData[1], rr.RData[2], rr.RData[3]))
		}
	}
	return ips
}

func intersectIPs(a, b []string) []string {
	mb := make(map[string]bool, len(b))
	for _, x := range b {
		mb[x] = true
	}
	var common []string
	for _, x := range a {
		if mb[x] {
			common = append(common, x)
		}
	}
	return common
}

func TestOutputComparisonMocked(t *testing.T) {
	m := testutil.NewMetrics()
	c := cache.NewMemory(0, nil)
	defer c.Close()

	mock := testutil.StartMockUpstream(t, "udp", func(data []byte) []byte {
		return testutil.BuildDNSResponse("example.com.", 1, net.ParseIP("1.2.3.4").To4())
	})
	defer mock.Close()

	g := testutil.NewTestGroup(t, mock.AddrStr())
	defer g.Close()

	rc := testutil.NewRuntimeConfig()
	ctx := context.Background()

	entry, _, err := resolve(ctx, "example.com.", 1, g, c, 512, "udp", rc, false, m, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if len(entry.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(entry.Answers))
	}
	if entry.Answers[0].RData[0] != 1 || entry.Answers[0].RData[1] != 2 ||
		entry.Answers[0].RData[2] != 3 || entry.Answers[0].RData[3] != 4 {
		t.Errorf("unexpected IP: %v", entry.Answers[0].RData)
	}
}
