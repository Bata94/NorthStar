package filter

import (
	"sort"
	"sync"
	"time"
)

type StatEntry struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type DayStats struct {
	Date       string  `json:"date"`
	Blocked    int64   `json:"blocked"`
	Total      int64   `json:"total"`
	BlockRatio float64 `json:"block_ratio"`
}

type StatsSummary struct {
	TotalBlocked int64       `json:"total_blocked"`
	TotalQueries int64       `json:"total_queries"`
	OverallRatio float64     `json:"overall_ratio"`
	TopDomains   []StatEntry `json:"top_domains"`
	TopClients   []StatEntry `json:"top_clients"`
	DailyTrend   []DayStats  `json:"daily_trend"`
	TrendDays    int         `json:"trend_days"`
}

type BlockingStats struct {
	mu             sync.RWMutex
	blockedDomains map[string]int64
	blockedClients map[string]int64
	dailyBlocks    map[string]int64
	dailyTotal     map[string]int64
	maxDomains     int
	maxClients     int
	retentionDays  int
}

func NewBlockingStats(maxDomains, maxClients, retentionDays int) *BlockingStats {
	if maxDomains < 1 {
		maxDomains = 1000
	}
	if maxClients < 1 {
		maxClients = 1000
	}
	if retentionDays < 1 {
		retentionDays = 30
	}
	return &BlockingStats{
		blockedDomains: make(map[string]int64),
		blockedClients: make(map[string]int64),
		dailyBlocks:    make(map[string]int64),
		dailyTotal:     make(map[string]int64),
		maxDomains:     maxDomains,
		maxClients:     maxClients,
		retentionDays:  retentionDays,
	}
}

func todayKey() string {
	return time.Now().UTC().Format("2006-01-02")
}

func (s *BlockingStats) RecordQuery(clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dailyTotal[todayKey()]++
}

func (s *BlockingStats) RecordBlock(domain, clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	today := todayKey()
	s.dailyBlocks[today]++
	s.dailyTotal[today]++

	if len(s.blockedDomains) >= s.maxDomains {
		for k := range s.blockedDomains {
			delete(s.blockedDomains, k)
			break
		}
	}
	s.blockedDomains[domain]++

	if len(s.blockedClients) >= s.maxClients {
		for k := range s.blockedClients {
			delete(s.blockedClients, k)
			break
		}
	}
	s.blockedClients[clientIP]++

	s.pruneDaily()
}

func (s *BlockingStats) pruneDaily() {
	cutoff := time.Now().UTC().AddDate(0, 0, -s.retentionDays)
	cutoffStr := cutoff.Format("2006-01-02")
	for k := range s.dailyBlocks {
		if k < cutoffStr {
			delete(s.dailyBlocks, k)
		}
	}
	for k := range s.dailyTotal {
		if k < cutoffStr {
			delete(s.dailyTotal, k)
		}
	}
}

func topN(m map[string]int64, n int) []StatEntry {
	if n < 1 {
		n = 10
	}
	entries := make([]StatEntry, 0, len(m))
	for k, v := range m {
		entries = append(entries, StatEntry{Key: k, Count: v})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

func (s *BlockingStats) TopBlockedDomains(n int) []StatEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return topN(s.blockedDomains, n)
}

func (s *BlockingStats) TopBlockedClients(n int) []StatEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return topN(s.blockedClients, n)
}

func (s *BlockingStats) DailyTrend(days int) []DayStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if days < 1 {
		days = 7
	}

	result := make([]DayStats, 0, days)
	now := time.Now().UTC()
	for i := days - 1; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		blocked := s.dailyBlocks[date]
		total := s.dailyTotal[date]
		ratio := 0.0
		if total > 0 {
			ratio = float64(blocked) / float64(total)
		}
		result = append(result, DayStats{
			Date:       date,
			Blocked:    blocked,
			Total:      total,
			BlockRatio: ratio,
		})
	}
	return result
}

func (s *BlockingStats) Summary(n int) StatsSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var totalBlocked int64
	for _, v := range s.dailyBlocks {
		totalBlocked += v
	}
	var totalQueries int64
	for _, v := range s.dailyTotal {
		totalQueries += v
	}
	ratio := 0.0
	if totalQueries > 0 {
		ratio = float64(totalBlocked) / float64(totalQueries)
	}

	if n < 1 {
		n = 10
	}

	trendDays := s.retentionDays
	if trendDays > 30 {
		trendDays = 30
	}
	trend := make([]DayStats, 0, trendDays)
	now := time.Now().UTC()
	for i := trendDays - 1; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		blocked := s.dailyBlocks[date]
		total := s.dailyTotal[date]
		r := 0.0
		if total > 0 {
			r = float64(blocked) / float64(total)
		}
		trend = append(trend, DayStats{
			Date:       date,
			Blocked:    blocked,
			Total:      total,
			BlockRatio: r,
		})
	}

	return StatsSummary{
		TotalBlocked: totalBlocked,
		TotalQueries: totalQueries,
		OverallRatio: ratio,
		TopDomains:   topN(s.blockedDomains, n),
		TopClients:   topN(s.blockedClients, n),
		DailyTrend:   trend,
		TrendDays:    trendDays,
	}
}

func (s *BlockingStats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockedDomains = make(map[string]int64)
	s.blockedClients = make(map[string]int64)
	s.dailyBlocks = make(map[string]int64)
	s.dailyTotal = make(map[string]int64)
}
