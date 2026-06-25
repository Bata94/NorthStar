package filter

import "strings"

// parseLine extracts a domain from a single line, supporting multiple formats:
//   - Bare:        example.com
//   - Wildcard:    *.example.com
//   - AdGuard:     ||example.com^
//   - Pi-hole:     0.0.0.0 example.com
//   - hosts:       127.0.0.1 example.com
//   - Comment:     # ... or ! ...
//
// Returns empty string for comments/blank lines.
func parseLine(line string) string {
	line = strings.TrimSpace(line)

	if line == "" {
		return ""
	}

	if line[0] == '#' || line[0] == '!' {
		return ""
	}

	if strings.HasPrefix(line, "||") {
		domain := line[2:]
		if idx := strings.IndexAny(domain, "^/"); idx >= 0 {
			domain = domain[:idx]
		}
		return strings.TrimSpace(domain)
	}

	if idx := strings.IndexAny(line, " \t"); idx >= 0 {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := fields[0]
			if isIP(ip) {
				return strings.TrimSpace(fields[1])
			}
			return strings.TrimSpace(fields[0])
		}
	}

	return strings.TrimRight(line, "^")
}

func isIP(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '.' && c != ':' && (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return strings.Contains(s, ".") || strings.Contains(s, ":")
}
