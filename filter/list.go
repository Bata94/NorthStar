package filter

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

type rule struct {
	raw      string
	wildcard bool
}

type List struct {
	mu    sync.RWMutex
	rules []rule
}

func New(paths []string) (*List, error) {
	l := &List{}
	if err := l.load(paths); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *List) load(paths []string) error {
	seen := make(map[string]bool)
	var rules []rule

	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := parseLine(scanner.Text())
			if line == "" {
				continue
			}
			if seen[line] {
				continue
			}
			seen[line] = true
			rules = append(rules, rule{
				raw:      line,
				wildcard: strings.HasPrefix(line, "*."),
			})
		}
		_ = f.Close()
		if err := scanner.Err(); err != nil {
			return err
		}
	}

	l.mu.Lock()
	l.rules = rules
	l.mu.Unlock()
	return nil
}

func (l *List) Reload(paths []string) error {
	return l.load(paths)
}

func (l *List) Match(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)

	l.mu.RLock()
	defer l.mu.RUnlock()

	for _, r := range l.rules {
		raw := strings.ToLower(r.raw)
		if r.wildcard {
			suffix := raw[1:]
			if len(domain) >= len(suffix) && domain[len(domain)-len(suffix):] == suffix {
				return true
			}
		} else if domain == raw {
			return true
		}
	}
	return false
}

func (l *List) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.rules)
}
