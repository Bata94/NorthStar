package log

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLevelFromString(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"WARN", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"WARNING", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"unknown", slog.LevelInfo},
		{"", slog.LevelInfo},
	}
	for _, tt := range tests {
		got := levelFromString(tt.input)
		if got != tt.want {
			t.Errorf("levelFromString(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		input string
		width int
		want  string
	}{
		{"ABC", 5, "ABC  "},
		{"ABCDE", 5, "ABCDE"},
		{"ABCDEF", 3, "ABC"},
		{"", 3, "   "},
	}
	for _, tt := range tests {
		result := string(pad(nil, tt.input, tt.width))
		if result != tt.want {
			t.Errorf("pad(%q, %d) = %q, want %q", tt.input, tt.width, result, tt.want)
		}
	}
}

func TestConsoleHandlerLevelEnforcement(t *testing.T) {
	var buf bytes.Buffer
	h := &consoleHandler{
		level: slog.LevelWarn,
		w:     &buf,
		mu:    &sync.Mutex{},
	}

	ctx := context.Background()

	if h.Enabled(ctx, slog.LevelDebug) {
		t.Error("debug should not be enabled at warn level")
	}
	if h.Enabled(ctx, slog.LevelInfo) {
		t.Error("info should not be enabled at warn level")
	}
	if !h.Enabled(ctx, slog.LevelWarn) {
		t.Error("warn should be enabled at warn level")
	}
	if !h.Enabled(ctx, slog.LevelError) {
		t.Error("error should be enabled at warn level")
	}
}

func TestConsoleHandlerFormat(t *testing.T) {
	var buf bytes.Buffer
	h := &consoleHandler{
		level: slog.LevelInfo,
		w:     &buf,
		color: true,
		mu:    &sync.Mutex{},
	}

	ctx := context.Background()
	r := slog.NewRecord(time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC), slog.LevelInfo, "test message", 0)
	r.AddAttrs(slog.String("key", "value"), slog.Int("num", 42))

	if err := h.Handle(ctx, r); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Error("expected 'test message' in output")
	}
	if !strings.Contains(output, "key=value") {
		t.Error("expected attribute in output")
	}
	if !strings.Contains(output, "num=42") {
		t.Error("expected numeric attribute in output")
	}
	if !strings.Contains(output, "INF") {
		t.Error("expected level label in output")
	}
}

func TestConsoleHandlerNoColor(t *testing.T) {
	var buf bytes.Buffer
	h := &consoleHandler{
		level: slog.LevelInfo,
		w:     &buf,
		color: false,
		mu:    &sync.Mutex{},
	}

	ctx := context.Background()
	r := slog.NewRecord(time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC), slog.LevelInfo, "no color test", 0)
	if err := h.Handle(ctx, r); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if strings.Contains(output, "\033[") {
		t.Error("expected no color codes")
	}
}

func TestMultiHandler(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	h1 := &consoleHandler{level: slog.LevelInfo, w: &buf1, mu: &sync.Mutex{}}
	h2 := &consoleHandler{level: slog.LevelInfo, w: &buf2, mu: &sync.Mutex{}}
	mh := &multiHandler{handlers: []slog.Handler{h1, h2}}

	ctx := context.Background()
	r := slog.NewRecord(time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC), slog.LevelInfo, "fanout", 0)
	if err := mh.Handle(ctx, r); err != nil {
		t.Fatal(err)
	}

	if buf1.Len() == 0 || buf2.Len() == 0 {
		t.Error("multiHandler should fan out to all handlers")
	}
}

func TestMultiHandlerWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := &consoleHandler{level: slog.LevelInfo, w: &buf, mu: &sync.Mutex{}}
	mh := &multiHandler{handlers: []slog.Handler{h}}

	mh2 := mh.WithAttrs([]slog.Attr{slog.String("global", "attr")})

	if mh2 == mh {
		t.Error("WithAttrs should return a new handler")
	}
}

func TestMultiHandlerWithGroup(t *testing.T) {
	h := &consoleHandler{level: slog.LevelInfo, w: &bytes.Buffer{}, mu: &sync.Mutex{}}
	mh := &multiHandler{handlers: []slog.Handler{h}}

	mh2 := mh.WithGroup("group")

	if mh2 == mh {
		t.Error("WithGroup should return a new handler")
	}
}

func TestConsoleHandlerWithAttrs(t *testing.T) {
	h := &consoleHandler{level: slog.LevelInfo, w: &bytes.Buffer{}, mu: &sync.Mutex{}}
	h2 := h.WithAttrs([]slog.Attr{slog.String("k", "v")})

	if h2 == h {
		t.Error("WithAttrs should return a new handler")
	}
}

func TestConsoleHandlerWithGroup(t *testing.T) {
	h := &consoleHandler{level: slog.LevelInfo, w: &bytes.Buffer{}, mu: &sync.Mutex{}}
	h2 := h.WithGroup("g")

	if h2 == h {
		t.Error("WithGroup should return a new handler")
	}
}

func TestNewDevMode(t *testing.T) {
	logger := New("debug", "dev")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	logger.Debug("dev debug test")
	logger.Info("dev info test")
}

func TestNewProdMode(t *testing.T) {
	logger := New("error", "prod")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	logger.Error("prod error test")
}
