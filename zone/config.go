package zone

import "github.com/bata94/northstar/dns"

func algorithmFromString(s string) uint8 {
	switch s {
	case "RSASHA256":
		return dns.AlgRSASHA256
	case "RSASHA512":
		return dns.AlgRSASHA512
	case "ECDSAP256SHA256":
		return dns.AlgECDSAP256
	case "ECDSAP384SHA384":
		return dns.AlgECDSAP384
	case "ED25519":
		return dns.AlgED25519
	case "ED448":
		return dns.AlgED448
	default:
		return dns.AlgECDSAP256
	}
}

func algorithmString(a uint8) string {
	switch a {
	case dns.AlgRSASHA256:
		return "RSASHA256"
	case dns.AlgRSASHA512:
		return "RSASHA512"
	case dns.AlgECDSAP256:
		return "ECDSAP256SHA256"
	case dns.AlgECDSAP384:
		return "ECDSAP384SHA384"
	case dns.AlgED25519:
		return "ED25519"
	case dns.AlgED448:
		return "ED448"
	default:
		return "ECDSAP256SHA256"
	}
}
