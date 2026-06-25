package acl

import (
	"fmt"
	"net"
	"strings"

	"github.com/bata94/northstar/config"
)

type Rule struct {
	Name     string
	Action   string // allow, refuse, drop, route
	Subnet   *net.IPNet
	Zone     string // domain suffix, empty = any
	Protocol string // udp, tcp, empty = any
	Upstream string // for route action, empty = any
}

type RuleSet struct {
	rules []*Rule
}

func NewRuleSet(configs []config.ACLConfig) (*RuleSet, error) {
	rs := &RuleSet{}
	for _, c := range configs {
		rule, err := ruleFromConfig(c)
		if err != nil {
			return nil, fmt.Errorf("acl %q: %w", c.Name, err)
		}
		rs.rules = append(rs.rules, rule)
	}
	return rs, nil
}

func ruleFromConfig(c config.ACLConfig) (*Rule, error) {
	if c.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	switch c.Action {
	case "allow", "refuse", "drop", "route":
	default:
		return nil, fmt.Errorf("invalid action %q", c.Action)
	}
	if c.Protocol != "" && c.Protocol != "udp" && c.Protocol != "tcp" {
		return nil, fmt.Errorf("invalid protocol %q", c.Protocol)
	}

	rule := &Rule{
		Name:     c.Name,
		Action:   c.Action,
		Zone:     c.Zone,
		Protocol: c.Protocol,
		Upstream: c.Upstream,
	}

	if c.Subnet != "" {
		_, ipnet, err := net.ParseCIDR(c.Subnet)
		if err != nil {
			return nil, fmt.Errorf("invalid subnet %q: %w", c.Subnet, err)
		}
		rule.Subnet = ipnet
	}

	if c.Zone != "" && c.Zone[len(c.Zone)-1] != '.' {
		rule.Zone = c.Zone + "."
	}

	return rule, nil
}

func (rs *RuleSet) Match(clientIP string, domain string, protocol string) *Rule {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil
	}

	for _, rule := range rs.rules {
		if rule.Subnet != nil && !rule.Subnet.Contains(ip) {
			continue
		}
		if rule.Zone != "" && !strings.HasSuffix(domain, rule.Zone) && domain != rule.Zone {
			continue
		}
		if rule.Protocol != "" && rule.Protocol != protocol {
			continue
		}
		return rule
	}
	return nil
}

func (rs *RuleSet) MatchUpstream(clientIP string, domain string, protocol string, upstreamName string) *Rule {
	if upstreamName == "" {
		return rs.Match(clientIP, domain, protocol)
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil
	}

	for _, rule := range rs.rules {
		if rule.Subnet != nil && !rule.Subnet.Contains(ip) {
			continue
		}
		if rule.Zone != "" && !strings.HasSuffix(domain, rule.Zone) && domain != rule.Zone {
			continue
		}
		if rule.Protocol != "" && rule.Protocol != protocol {
			continue
		}
		if rule.Upstream != "" && rule.Upstream != upstreamName {
			continue
		}
		return rule
	}
	return nil
}

func (rs *RuleSet) Rules() []*Rule {
	return rs.rules
}

func (rs *RuleSet) Replace(rules []*Rule) {
	rs.rules = rules
}
