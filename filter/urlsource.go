package filter

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type URLSource struct {
	url             string
	refreshInterval time.Duration
	cacheDir        string
	localPath       string
	etag            string
	client          *http.Client
	stopCh          chan struct{}
	closeOnce       sync.Once
	wg              sync.WaitGroup
	mu              sync.RWMutex
}

func NewURLSource(url string, intervalMinutes int, cacheDir string) *URLSource {
	if intervalMinutes < 1 {
		intervalMinutes = 1440
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(url)))[:16]
	localPath := filepath.Join(cacheDir, "urlsource-"+hash+".txt")

	return &URLSource{
		url:             url,
		refreshInterval: time.Duration(intervalMinutes) * time.Minute,
		cacheDir:        cacheDir,
		localPath:       localPath,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
}

func (s *URLSource) Start(ctx context.Context, onUpdate func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		if err := s.fetch(); err != nil {
			slog.Warn("URL source initial fetch failed", "url", s.url, "error", err)
		} else {
			onUpdate()
		}

		ticker := time.NewTicker(s.refreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := s.fetch(); err != nil {
					slog.Warn("URL source refresh failed", "url", s.url, "error", err)
				} else {
					onUpdate()
				}
			case <-s.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *URLSource) fetch() error {
	req, err := http.NewRequest(http.MethodGet, s.url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	s.mu.RLock()
	etag := s.etag
	s.mu.RUnlock()

	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("failed to close response body", "url", s.url, "error", err)
		}
	}()

	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	if err := os.MkdirAll(s.cacheDir, 0755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	tmpFile, err := os.CreateTemp(s.cacheDir, "urlsource-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	written, err := io.Copy(tmpFile, resp.Body)
	if err != nil {
		if cerr := tmpFile.Close(); cerr != nil {
			slog.Error("failed to close temp file after copy error", "error", cerr)
		}
		if rerr := os.Remove(tmpFile.Name()); rerr != nil {
			slog.Error("failed to remove temp file after copy error", "error", rerr)
		}
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		if rerr := os.Remove(tmpFile.Name()); rerr != nil {
			slog.Error("failed to remove temp file after close error", "error", rerr)
		}
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpFile.Name(), s.localPath); err != nil {
		if rerr := os.Remove(tmpFile.Name()); rerr != nil {
			slog.Error("failed to remove temp file after rename error", "error", rerr)
		}
		return fmt.Errorf("rename temp file: %w", err)
	}

	s.mu.Lock()
	s.etag = resp.Header.Get("ETag")
	s.mu.Unlock()

	slog.Debug("URL source fetched", "url", s.url, "bytes", written, "path", s.localPath)
	return nil
}

func (s *URLSource) LocalPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localPath
}

func (s *URLSource) URL() string {
	return s.url
}

func (s *URLSource) Close() {
	s.closeOnce.Do(func() {
		close(s.stopCh)
		s.wg.Wait()
	})
}
