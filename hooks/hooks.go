// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package hooks

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/metrics"
)

type Lifecycle int

const (
	PreResolve Lifecycle = iota
	PostResolve
	PreResponse
	PostResponse
)

var (
	ErrHookStop    = errors.New("hook: stop pipeline")
	ErrRateLimited = errors.New("rate limit exceeded")
	ErrBlocked     = errors.New("query blocked")
)

type Context struct {
	Ctx               context.Context
	Request           *dns.Message
	Response          *dns.Message
	ClientIP          string
	Network           string
	Cache             cache.Cache
	Metrics           *metrics.Metrics
	Send              func([]byte) error
	Entry             *cache.Entry
	Upstream          string
	ECSData           []byte
	PreferredUpstream string
	StartTime         time.Time
}

type Hook interface {
	Name() string
	Lifecycle() Lifecycle
	Priority() int
	Enabled() bool
	Handle(ctx *Context) error
}

type Pipeline struct {
	mu           sync.RWMutex
	preResolve   []Hook
	postResolve  []Hook
	preResponse  []Hook
	postResponse []Hook
}

func NewPipeline() *Pipeline {
	return &Pipeline{}
}

func insertSorted(hooks []Hook, hook Hook) []Hook {
	i := 0
	for i < len(hooks) && hooks[i].Priority() <= hook.Priority() {
		i++
	}
	hooks = append(hooks, nil)
	copy(hooks[i+1:], hooks[i:])
	hooks[i] = hook
	return hooks
}

func (p *Pipeline) Register(hook Hook) {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch hook.Lifecycle() {
	case PreResolve:
		p.preResolve = insertSorted(p.preResolve, hook)
	case PostResolve:
		p.postResolve = insertSorted(p.postResolve, hook)
	case PreResponse:
		p.preResponse = insertSorted(p.preResponse, hook)
	case PostResponse:
		p.postResponse = insertSorted(p.postResponse, hook)
	}
}

func (p *Pipeline) Run(lifecycle Lifecycle, ctx *Context) error {
	p.mu.RLock()
	var hooks []Hook
	switch lifecycle {
	case PreResolve:
		hooks = p.preResolve
	case PostResolve:
		hooks = p.postResolve
	case PreResponse:
		hooks = p.preResponse
	case PostResponse:
		hooks = p.postResponse
	}
	p.mu.RUnlock()

	for _, hook := range hooks {
		if !hook.Enabled() {
			continue
		}
		if err := hook.Handle(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *Pipeline) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.preResolve = nil
	p.postResolve = nil
	p.preResponse = nil
	p.postResponse = nil
}
