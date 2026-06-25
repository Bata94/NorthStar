package filter

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewList(t *testing.T) {
	path := writeTempFile(t, "example.com\n*.evil.com\n# comment\n0.0.0.0 tracked.com\n||ads.com^\n! another comment\n\n")

	l, err := New([]string{path})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		domain string
		match  bool
	}{
		{"example.com", true},
		{"sub.example.com", false},
		{"evil.com", false}, // bare *.evil.com matches subdomains only
		{"sub.evil.com", true},
		{"tracked.com", true},
		{"ads.com", true},
		{"sub.ads.com", false},
		{"good.com", false},
		{"example.com.", true},
		{"EXAMPLE.COM", true},  // case insensitive
		{"SUB.EVIL.COM", true}, // case insensitive wildcard
	}

	for _, tt := range tests {
		got := l.Match(tt.domain)
		if got != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.domain, got, tt.match)
		}
	}
}

func TestListReload(t *testing.T) {
	path := writeTempFile(t, "blocked.com\n")
	l, err := New([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if !l.Match("blocked.com") {
		t.Fatal("expected blocked.com to match")
	}

	if err := os.WriteFile(path, []byte("newblocked.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := l.Reload([]string{path}); err != nil {
		t.Fatal(err)
	}
	if l.Match("blocked.com") {
		t.Fatal("expected blocked.com to no longer match after reload")
	}
	if !l.Match("newblocked.com") {
		t.Fatal("expected newblocked.com to match after reload")
	}
}

func TestNewFilter(t *testing.T) {
	blockPath := writeTempFile(t, "bad.com\n*.evil.net\n")
	allowPath := writeTempFile(t, "important.bad.com\n")

	f, err := NewFilter([]string{blockPath}, []string{allowPath})
	if err != nil {
		t.Fatal(err)
	}

	if !f.IsBlocked("bad.com") {
		t.Error("expected bad.com to be blocked")
	}
	if !f.IsBlocked("sub.evil.net") {
		t.Error("expected sub.evil.net to be blocked")
	}
	if f.IsBlocked("important.bad.com") {
		t.Error("expected important.bad.com to be allowed despite blocklist")
	}
	if f.IsBlocked("good.com") {
		t.Error("expected good.com to not be blocked")
	}
}

func TestNewFilterNil(t *testing.T) {
	var f *Filter
	if f.IsBlocked("anything") {
		t.Error("nil filter should not block anything")
	}
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"example.com", "example.com"},
		{"  example.com  ", "example.com"},
		{"*.evil.com", "*.evil.com"},
		{"", ""},
		{"# comment", ""},
		{"! adblock comment", ""},
		{"||ads.com^", "ads.com"},
		{"||tracker.com^third-party", "tracker.com"},
		{"0.0.0.0 blocked.com", "blocked.com"},
		{"127.0.0.1 blocked.com", "blocked.com"},
		{"::1 blocked6.com", "blocked6.com"},
		{"  127.0.0.1   spaced.com  ", "spaced.com"},
	}

	for _, tt := range tests {
		got := parseLine(tt.line)
		if got != tt.want {
			t.Errorf("parseLine(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestRPZ(t *testing.T) {
	path := writeTempFile(t, "malware.com\n*.phish.net\n")
	rpz, err := NewRPZSet([]struct{ Path, Action string }{{path, "sinkhole"}})
	if err != nil {
		t.Fatal(err)
	}

	action, ok := rpz.Match("malware.com")
	if !ok || action != "sinkhole" {
		t.Errorf("Match(malware.com) = (%q, %v), want (sinkhole, true)", action, ok)
	}

	action, ok = rpz.Match("sub.phish.net")
	if !ok || action != "sinkhole" {
		t.Errorf("Match(sub.phish.net) = (%q, %v), want (sinkhole, true)", action, ok)
	}

	_, ok = rpz.Match("good.com")
	if ok {
		t.Error("expected good.com to not match RPZ")
	}
}

func TestRPZEmpty(t *testing.T) {
	var rs *RPZSet
	_, ok := rs.Match("anything")
	if ok {
		t.Error("nil RPZSet should not match")
	}
}

func TestListLen(t *testing.T) {
	path := writeTempFile(t, "a.com\nb.com\nc.com\n")
	l, err := New([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if l.Len() != 3 {
		t.Errorf("Len() = %d, want 3", l.Len())
	}
}

func TestFilterLen(t *testing.T) {
	blockPath := writeTempFile(t, "a.com\nb.com\n")
	allowPath := writeTempFile(t, "c.com\n")
	f, err := NewFilter([]string{blockPath}, []string{allowPath})
	if err != nil {
		t.Fatal(err)
	}
	if f.BlocklistLen() != 2 {
		t.Errorf("BlocklistLen() = %d, want 2", f.BlocklistLen())
	}
	if f.AllowlistLen() != 1 {
		t.Errorf("AllowlistLen() = %d, want 1", f.AllowlistLen())
	}
}
