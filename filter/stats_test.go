package filter

import (
	"testing"
)

func TestBlockingStatsRecord(t *testing.T) {
	s := NewBlockingStats(100, 100, 30)

	s.RecordQuery("10.0.0.1")
	s.RecordBlock("bad.com", "10.0.0.1")
	s.RecordBlock("evil.net", "10.0.0.1")
	s.RecordBlock("bad.com", "10.0.0.2")

	domains := s.TopBlockedDomains(10)
	if len(domains) != 2 {
		t.Fatalf("expected 2 blocked domains, got %d", len(domains))
	}
	if domains[0].Key != "bad.com" || domains[0].Count != 2 {
		t.Errorf("expected bad.com:2, got %s:%d", domains[0].Key, domains[0].Count)
	}

	clients := s.TopBlockedClients(10)
	if len(clients) != 2 {
		t.Fatalf("expected 2 blocked clients, got %d", len(clients))
	}
}

func TestBlockingStatsTopDomains(t *testing.T) {
	s := NewBlockingStats(100, 100, 30)

	s.RecordBlock("a.com", "1")
	s.RecordBlock("b.com", "1")
	s.RecordBlock("a.com", "1")
	s.RecordBlock("c.com", "1")
	s.RecordBlock("a.com", "1")

	domains := s.TopBlockedDomains(2)
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}
	if domains[0].Key != "a.com" || domains[0].Count != 3 {
		t.Errorf("expected a.com:3, got %s:%d", domains[0].Key, domains[0].Count)
	}
	if domains[1].Key != "b.com" {
		t.Errorf("expected b.com, got %s", domains[1].Key)
	}

	// Test with n=0 (should default to 10)
	all := s.TopBlockedDomains(0)
	if len(all) != 3 {
		t.Errorf("expected 3 domains with n=0, got %d", len(all))
	}
}

func TestBlockingStatsReset(t *testing.T) {
	s := NewBlockingStats(100, 100, 30)

	s.RecordBlock("bad.com", "10.0.0.1")
	s.RecordQuery("10.0.0.1")

	s.Reset()

	if len(s.TopBlockedDomains(10)) != 0 {
		t.Error("expected empty domains after reset")
	}
	if len(s.TopBlockedClients(10)) != 0 {
		t.Error("expected empty clients after reset")
	}

	summary := s.Summary(10)
	if summary.TotalBlocked != 0 {
		t.Errorf("expected 0 total blocked, got %d", summary.TotalBlocked)
	}
}

func TestBlockingStatsSummary(t *testing.T) {
	s := NewBlockingStats(100, 100, 30)

	s.RecordQuery("10.0.0.1")
	s.RecordBlock("bad.com", "10.0.0.1")
	s.RecordBlock("evil.net", "10.0.0.1")
	s.RecordQuery("10.0.0.2")

	summary := s.Summary(10)

	if summary.TotalBlocked != 2 {
		t.Errorf("expected 2 total blocked, got %d", summary.TotalBlocked)
	}
	if summary.TotalQueries != 4 {
		t.Errorf("expected 4 total queries, got %d", summary.TotalQueries)
	}
	if summary.OverallRatio != 0.5 {
		t.Errorf("expected 0.5 ratio, got %f", summary.OverallRatio)
	}

	if len(summary.TopDomains) != 2 {
		t.Errorf("expected 2 top domains, got %d", len(summary.TopDomains))
	}

	if len(summary.DailyTrend) == 0 {
		t.Error("expected non-empty daily trend")
	}
}

func TestBlockingStatsMaxEntries(t *testing.T) {
	s := NewBlockingStats(3, 100, 30)

	for i := 0; i < 10; i++ {
		s.RecordBlock("domain.com", "10.0.0.1")
	}

	domains := s.TopBlockedDomains(10)
	if len(domains) > 5 {
		t.Errorf("expected at most 5 domains (evicted), got %d", len(domains))
	}
}

func TestBlockingStatsDailyTrend(t *testing.T) {
	s := NewBlockingStats(100, 100, 30)

	s.RecordBlock("bad.com", "10.0.0.1")

	trend := s.DailyTrend(3)
	if len(trend) != 3 {
		t.Fatalf("expected 3 days, got %d", len(trend))
	}

	if trend[2].Blocked != 1 {
		t.Errorf("expected 1 block on today, got %d", trend[2].Blocked)
	}
	if trend[2].Total != 1 {
		t.Errorf("expected 1 total on today, got %d", trend[2].Total)
	}
}

func TestBlockingStatsRecordQuery(t *testing.T) {
	s := NewBlockingStats(100, 100, 30)

	s.RecordQuery("10.0.0.1")
	s.RecordQuery("10.0.0.2")
	s.RecordQuery("10.0.0.1")

	summary := s.Summary(10)
	if summary.TotalQueries != 3 {
		t.Errorf("expected 3 queries, got %d", summary.TotalQueries)
	}
	if summary.TotalBlocked != 0 {
		t.Errorf("expected 0 blocked, got %d", summary.TotalBlocked)
	}
}
