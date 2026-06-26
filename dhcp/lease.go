package dhcp

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type Lease struct {
	Hostname string
	IP       net.IP
	MAC      string
	Starts   time.Time
	Ends     time.Time
}

type Parser interface {
	Parse(r io.Reader) ([]Lease, error)
}

type DnsmasqParser struct{}

func (DnsmasqParser) Parse(r io.Reader) ([]Lease, error) {
	var leases []Lease
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lease, ok := parseDnsmasqLine(line)
		if ok {
			leases = append(leases, lease)
		}
	}
	return leases, scanner.Err()
}

func parseDnsmasqLine(line string) (Lease, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Lease{}, false
	}

	expiryUnix, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return Lease{}, false
	}

	mac := fields[1]
	ip := net.ParseIP(fields[2])
	if ip == nil {
		return Lease{}, false
	}

	hostname := fields[3]
	if hostname == "*" {
		hostname = ""
	}

	now := time.Now()
	var ends time.Time
	if expiryUnix == 0 {
		ends = now.Add(24 * time.Hour)
	} else {
		ends = time.Unix(expiryUnix, 0)
	}

	return Lease{
		Hostname: hostname,
		IP:       ip,
		MAC:      mac,
		Starts:   now,
		Ends:     ends,
	}, true
}

func ParseLeasesFile(r io.Reader, format string) ([]Lease, error) {
	var p Parser
	switch format {
	case "dnsmasq":
		p = DnsmasqParser{}
	default:
		p = DnsmasqParser{}
	}
	return p.Parse(r)
}

func (l Lease) Expired() bool {
	return time.Now().After(l.Ends)
}

func (l Lease) HasHostname() bool {
	return l.Hostname != ""
}
