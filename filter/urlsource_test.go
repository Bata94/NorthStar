package filter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestURLSourceFetchNew(t *testing.T) {
	content := "bad.com\nevil.net\n"
	etag := `"v1"`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer ts.Close()

	cacheDir := t.TempDir()
	s := NewURLSource(ts.URL, 60, cacheDir)

	if err := s.fetch(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(s.LocalPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Errorf("expected %q, got %q", content, string(data))
	}

	if s.etag != etag {
		t.Errorf("expected etag %q, got %q", etag, s.etag)
	}
}

func TestURLSourceFetchCached(t *testing.T) {
	content := "cached.com\n"
	etag := `"v2"`
	fetchCount := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer ts.Close()

	cacheDir := t.TempDir()
	s := NewURLSource(ts.URL, 60, cacheDir)

	if err := s.fetch(); err != nil {
		t.Fatal(err)
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount)
	}

	if err := s.fetch(); err != nil {
		t.Fatal(err)
	}
	if fetchCount != 2 {
		t.Errorf("expected 2 fetches, got %d", fetchCount)
	}
}

func TestURLSourcePeriodicRefresh(t *testing.T) {
	content := "refreshed.com\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer ts.Close()

	cacheDir := t.TempDir()
	s := NewURLSource(ts.URL, 1, cacheDir) // very short interval

	updates := make(chan struct{}, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.Start(ctx, func() {
		updates <- struct{}{}
	})

	select {
	case <-updates:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for initial fetch")
	}

	s.Close()
}

func TestURLSourceAtomicWrite(t *testing.T) {
	content := "atomic.com\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer ts.Close()

	cacheDir := t.TempDir()
	s := NewURLSource(ts.URL, 60, cacheDir)

	if err := s.fetch(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(s.LocalPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Errorf("expected %q, got %q", content, string(data))
	}
}

func TestURLSourceErrorRecovery(t *testing.T) {
	cacheDir := t.TempDir()

	s := NewURLSource("http://127.0.0.1:1/nonexistent", 60, cacheDir)

	err := s.fetch()
	if err == nil {
		t.Error("expected error for unreachable URL")
	}
}

func TestURLSourceLocalPath(t *testing.T) {
	s := NewURLSource("https://example.com/list.txt", 60, "/tmp/cache")

	if s.URL() != "https://example.com/list.txt" {
		t.Errorf("unexpected URL: %s", s.URL())
	}

	expectedPath := filepath.Join("/tmp/cache", "urlsource-")
	if len(s.LocalPath()) < len(expectedPath) || s.LocalPath()[:len(expectedPath)] != expectedPath {
		t.Errorf("unexpected local path: %s", s.LocalPath())
	}
}

func TestURLSourceCloseIdempotent(t *testing.T) {
	s := NewURLSource("https://example.com", 60, t.TempDir())
	s.Close()
	s.Close()
}

func TestURLSourceHashURL(t *testing.T) {
	s1 := NewURLSource("https://example.com/a", 60, t.TempDir())
	s2 := NewURLSource("https://example.com/b", 60, t.TempDir())
	if s1.LocalPath() == s2.LocalPath() {
		t.Error("expected different paths for different URLs")
	}
}
