package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

const (
	reset  = "\033[0m"
	cyan   = "\033[36m"
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
)

var levelStyle = map[slog.Level]struct {
	Label string
	Color string
}{
	slog.LevelDebug: {"DBG", cyan},
	slog.LevelInfo:  {"INF", green},
	slog.LevelWarn:  {"WRN", yellow},
	slog.LevelError: {"ERR", red},
}

type consoleHandler struct {
	level  slog.Leveler
	attrs  []slog.Attr
	groups []string
	color  bool
	mu     *sync.Mutex
	w      io.Writer
}

func (h *consoleHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *consoleHandler) Handle(_ context.Context, r slog.Record) error {
	b := make([]byte, 0, 256)
	b = append(b, r.Time.Format("15:04:05")...)

	cfg := levelStyle[r.Level]
	if h.color {
		b = append(b, "  \033[0m"...)
		b = append(b, cfg.Color...)
	} else {
		b = append(b, "  "...)
	}
	b = pad(b, cfg.Label, 3)
	if h.color {
		b = append(b, reset...)
	}
	b = append(b, "  "...)
	b = append(b, r.Message...)

	prefix := strings.Join(h.groups, ".")
	attrs := h.attrs
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	for _, a := range attrs {
		if a.Equal(slog.Attr{}) {
			continue
		}
		val := a.Value
		if val.Kind() == slog.KindGroup {
			continue
		}
		b = append(b, "  "...)
		if prefix != "" {
			b = append(b, prefix...)
			b = append(b, '.')
		}
		b = append(b, a.Key...)
		b = append(b, '=')
		b = fmt.Append(b, val.Any())
	}

	b = append(b, '\n')

	h.mu.Lock()
	_, err := h.w.Write(b)
	h.mu.Unlock()
	return err
}

func (h *consoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append(n.attrs, attrs...)
	return &n
}

func (h *consoleHandler) WithGroup(name string) slog.Handler {
	n := *h
	n.groups = append(n.groups, name)
	return &n
}

func pad(b []byte, s string, w int) []byte {
	if len(s) > w {
		return append(b, s[:w]...)
	}
	b = append(b, s...)
	for i := len(s); i < w; i++ {
		b = append(b, ' ')
	}
	return b
}

type multiHandler struct {
	handlers []slog.Handler
}

func (h *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, hand := range h.handlers {
		if hand.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, hand := range h.handlers {
		if err := hand.Handle(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, hand := range h.handlers {
		handlers[i] = hand.WithAttrs(attrs)
	}
	return &multiHandler{handlers: handlers}
}

func (h *multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, hand := range h.handlers {
		handlers[i] = hand.WithGroup(name)
	}
	return &multiHandler{handlers: handlers}
}

func levelFromString(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func New(levelStr, mode string) *slog.Logger {
	level := levelFromString(levelStr)
	color := mode == "dev" || mode == "development"

	var handlers []slog.Handler

	handlers = append(handlers, &consoleHandler{
		level: level,
		w:     os.Stdout,
		color: color,
		mu:    &sync.Mutex{},
	})

	if f, err := os.OpenFile("northstar.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		handlers = append(handlers, slog.NewJSONHandler(f, &slog.HandlerOptions{Level: level}))
	}

	return slog.New(&multiHandler{handlers: handlers})
}
