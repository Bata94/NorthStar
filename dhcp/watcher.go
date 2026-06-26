package dhcp

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bata94/northstar/dns"
)

type Watcher struct {
	mu       sync.RWMutex
	leases   []Lease
	path     string
	format   string
	interval time.Duration
	done     chan struct{}
	onChange func()
	lastMod  time.Time
	lastSize int64
}

func NewWatcher(path, format string, interval time.Duration) *Watcher {
	return &Watcher{
		path:     path,
		format:   format,
		interval: interval,
		done:     make(chan struct{}),
	}
}

func (w *Watcher) SetOnChange(fn func()) {
	w.onChange = fn
}

func (w *Watcher) Start(ctx <-chan struct{}) error {
	if _, err := os.Stat(w.path); os.IsNotExist(err) {
		return fmt.Errorf("dhcp: lease file %q does not exist", w.path)
	}

	if err := w.refresh(); err != nil {
		return err
	}

	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx:
				return
			case <-ticker.C:
				if w.fileChanged() {
					_ = w.refresh()
					if w.onChange != nil {
						w.onChange()
					}
				}
			}
		}
	}()

	return nil
}

func (w *Watcher) Stop() {
	close(w.done)
}

func (w *Watcher) Leases() []Lease {
	w.mu.RLock()
	defer w.mu.RUnlock()
	result := make([]Lease, len(w.leases))
	copy(result, w.leases)
	return result
}

func (w *Watcher) ActiveLeases() []Lease {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var result []Lease
	for _, l := range w.leases {
		if !l.Expired() && l.HasHostname() {
			result = append(result, l)
		}
	}
	return result
}

func (w *Watcher) fileChanged() bool {
	info, err := os.Stat(w.path)
	if err != nil {
		return false
	}
	if info.ModTime() != w.lastMod || info.Size() != w.lastSize {
		w.lastMod = info.ModTime()
		w.lastSize = info.Size()
		return true
	}
	return false
}

func (w *Watcher) refresh() error {
	f, err := os.Open(w.path)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "dhcp: error closing lease file: %v\n", err)
		}
	}()

	leases, err := ParseLeasesFile(f, w.format)
	if err != nil {
		return err
	}

	info, _ := os.Stat(w.path)
	if info != nil {
		w.lastMod = info.ModTime()
		w.lastSize = info.Size()
	}

	w.mu.Lock()
	w.leases = leases
	w.mu.Unlock()

	return nil
}

func BuildDHCPZone(domain string, ttl uint32, leases []Lease) ([]dns.ResourceRecord, []dns.ResourceRecord) {
	var answers []dns.ResourceRecord

	seenHostnames := make(map[string]bool)

	for _, lease := range leases {
		if lease.Expired() || !lease.HasHostname() {
			continue
		}

		hostname := lease.Hostname
		if seenHostnames[hostname] {
			continue
		}
		seenHostnames[hostname] = true

		fqdn := hostname + "." + domain

		if ip4 := lease.IP.To4(); ip4 != nil {
			answers = append(answers, dns.ResourceRecord{
				Name:     fqdn,
				Type:     dns.TypeA,
				Class:    1,
				TTL:      ttl,
				RDLength: uint16(len(ip4)),
				RData:    ip4,
			})

			ptrName := reverseIPv4(lease.IP) + ".in-addr.arpa."
			ptrData := encodeDNSName(fqdn)
			answers = append(answers, dns.ResourceRecord{
				Name:     ptrName,
				Type:     dns.TypePTR,
				Class:    1,
				TTL:      ttl,
				RDLength: uint16(len(ptrData)),
				RData:    ptrData,
			})
		}
	}

	return answers, nil
}

func reverseIPv4(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])
}

func encodeDNSName(name string) []byte {
	if name == "" || name == "." {
		return []byte{0}
	}
	name = strings.TrimSuffix(name, ".")
	var buf []byte
	for _, label := range strings.Split(name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0)
}
