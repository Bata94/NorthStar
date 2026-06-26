package zone

import (
	"crypto"
	"net"

	"github.com/bata94/northstar/dns"
)

type Record interface {
	DNSName() string
	DNSType() uint16
	TTL() uint32
	RData() ([]byte, error)
}

type ARecord struct {
	Name   string
	TTLSec uint32
	IP     net.IP
}

func (r *ARecord) DNSName() string { return r.Name }
func (r *ARecord) DNSType() uint16 { return dns.TypeA }
func (r *ARecord) TTL() uint32     { return r.TTLSec }
func (r *ARecord) RData() ([]byte, error) {
	ip4 := r.IP.To4()
	if ip4 == nil {
		return nil, ErrNotAnIP
	}
	return []byte(ip4), nil
}

type AAAARecord struct {
	Name   string
	TTLSec uint32
	IP     net.IP
}

func (r *AAAARecord) DNSName() string { return r.Name }
func (r *AAAARecord) DNSType() uint16 { return dns.TypeAAAA }
func (r *AAAARecord) TTL() uint32     { return r.TTLSec }
func (r *AAAARecord) RData() ([]byte, error) {
	ip16 := r.IP.To16()
	if ip16 == nil {
		return nil, ErrNotAnIP
	}
	return []byte(ip16), nil
}

type CNAMERecord struct {
	Name   string
	TTLSec uint32
	Target string
}

func (r *CNAMERecord) DNSName() string { return r.Name }
func (r *CNAMERecord) DNSType() uint16 { return dns.TypeCNAME }
func (r *CNAMERecord) TTL() uint32     { return r.TTLSec }
func (r *CNAMERecord) RData() ([]byte, error) {
	return encodeName(r.Target), nil
}

type NSRecord struct {
	Name   string
	TTLSec uint32
	Target string
}

func (r *NSRecord) DNSName() string { return r.Name }
func (r *NSRecord) DNSType() uint16 { return dns.TypeNS }
func (r *NSRecord) TTL() uint32     { return r.TTLSec }
func (r *NSRecord) RData() ([]byte, error) {
	return encodeName(r.Target), nil
}

type MXRecord struct {
	Name       string
	TTLSec     uint32
	Preference uint16
	Host       string
}

func (r *MXRecord) DNSName() string { return r.Name }
func (r *MXRecord) DNSType() uint16 { return dns.TypeMX }
func (r *MXRecord) TTL() uint32     { return r.TTLSec }
func (r *MXRecord) RData() ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = byte(r.Preference >> 8)
	buf[1] = byte(r.Preference)
	buf = append(buf, encodeName(r.Host)...)
	return buf, nil
}

type SOARecord struct {
	Name    string
	TTLSec  uint32
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

func (r *SOARecord) DNSName() string { return r.Name }
func (r *SOARecord) DNSType() uint16 { return dns.TypeSOA }
func (r *SOARecord) TTL() uint32     { return r.TTLSec }
func (r *SOARecord) RData() ([]byte, error) {
	buf := encodeName(r.MName)
	buf = append(buf, encodeName(r.RName)...)
	buf = appendU32(buf, r.Serial)
	buf = appendU32(buf, r.Refresh)
	buf = appendU32(buf, r.Retry)
	buf = appendU32(buf, r.Expire)
	buf = appendU32(buf, r.Minimum)
	return buf, nil
}

type TXTRecord struct {
	Name   string
	TTLSec uint32
	Data   string
}

func (r *TXTRecord) DNSName() string { return r.Name }
func (r *TXTRecord) DNSType() uint16 { return dns.TypeTXT }
func (r *TXTRecord) TTL() uint32     { return r.TTLSec }
func (r *TXTRecord) RData() ([]byte, error) {
	text := []byte(r.Data)
	buf := make([]byte, 0, 1+len(text))
	if len(text) > 255 {
		for i := 0; i < len(text); i += 255 {
			end := i + 255
			if end > len(text) {
				end = len(text)
			}
			buf = append(buf, byte(end-i))
			buf = append(buf, text[i:end]...)
		}
	} else {
		buf = append(buf, byte(len(text)))
		buf = append(buf, text...)
	}
	return buf, nil
}

type SRVRecord struct {
	Name     string
	TTLSec   uint32
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

func (r *SRVRecord) DNSName() string { return r.Name }
func (r *SRVRecord) DNSType() uint16 { return dns.TypeSRV }
func (r *SRVRecord) TTL() uint32     { return r.TTLSec }
func (r *SRVRecord) RData() ([]byte, error) {
	buf := make([]byte, 6)
	buf[0] = byte(r.Priority >> 8)
	buf[1] = byte(r.Priority)
	buf[2] = byte(r.Weight >> 8)
	buf[3] = byte(r.Weight)
	buf[4] = byte(r.Port >> 8)
	buf[5] = byte(r.Port)
	buf = append(buf, encodeName(r.Target)...)
	return buf, nil
}

type DNSKEYRecord struct {
	Name      string
	TTLSec    uint32
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey []byte
}

func (r *DNSKEYRecord) DNSName() string { return r.Name }
func (r *DNSKEYRecord) DNSType() uint16 { return dns.TypeDNSKEY }
func (r *DNSKEYRecord) TTL() uint32     { return r.TTLSec }
func (r *DNSKEYRecord) RData() ([]byte, error) {
	buf := make([]byte, 4)
	buf[0] = byte(r.Flags >> 8)
	buf[1] = byte(r.Flags)
	buf[2] = r.Protocol
	buf[3] = r.Algorithm
	buf = append(buf, r.PublicKey...)
	return buf, nil
}

type RRSIGRecord struct {
	Name          string
	TTLSec        uint32
	TypeCovered   uint16
	Algorithm     uint8
	Labels        uint8
	OriginalTTL   uint32
	SigExpiration uint32
	SigInception  uint32
	KeyTag        uint16
	SignerName    string
	Signature     []byte
}

func (r *RRSIGRecord) DNSName() string { return r.Name }
func (r *RRSIGRecord) DNSType() uint16 { return dns.TypeRRSIG }
func (r *RRSIGRecord) TTL() uint32     { return r.TTLSec }
func (r *RRSIGRecord) RData() ([]byte, error) {
	buf := make([]byte, 18)
	binaryBigEndianPutUint16(buf[0:2], r.TypeCovered)
	buf[2] = r.Algorithm
	buf[3] = r.Labels
	binaryBigEndianPutUint32(buf[4:8], r.OriginalTTL)
	binaryBigEndianPutUint32(buf[8:12], r.SigExpiration)
	binaryBigEndianPutUint32(buf[12:16], r.SigInception)
	binaryBigEndianPutUint16(buf[16:18], r.KeyTag)
	buf = append(buf, encodeName(r.SignerName)...)
	buf = append(buf, r.Signature...)
	return buf, nil
}

type NSECRecord struct {
	Name       string
	TTLSec     uint32
	NextDomain string
	Types      []uint16
}

func (r *NSECRecord) DNSName() string { return r.Name }
func (r *NSECRecord) DNSType() uint16 { return dns.TypeNSEC }
func (r *NSECRecord) TTL() uint32     { return r.TTLSec }
func (r *NSECRecord) RData() ([]byte, error) {
	buf := encodeName(r.NextDomain)
	bitmap := make([]byte, 32)
	for _, t := range r.Types {
		window := t / 256
		offset := (t % 256) / 8
		bit := t % 8
		blockIdx := 0
		for i := 0; i < len(bitmap); i += 32 {
			if int(bitmap[i]) == int(window) {
				blockIdx = i
				break
			}
			if bitmap[i] == 0 && i == blockIdx {
				bitmap[i] = byte(window)
				blockIdx = i
				break
			}
		}
		lengthPos := blockIdx + 1
		bitPos := blockIdx + 2 + int(offset)
		for bitPos >= len(bitmap) {
			bitmap = append(bitmap, 0)
		}
		bitmap[bitPos] |= 1 << (7 - bit)
		if bitmap[lengthPos] < byte(offset+1) {
			bitmap[lengthPos] = byte(offset + 1)
		}
	}
	// trim trailing zero bytes but keep window block structure
	end := len(bitmap)
	for end > 0 && bitmap[end-1] == 0 {
		end--
	}
	buf = append(buf, bitmap[:end]...)
	return buf, nil
}

type DNSSECConfig struct {
	Enabled   bool
	Algorithm uint8
	KeyFile   string
	ZSKFile   string
	NSEC3     bool
}

type ZoneView struct {
	Name    string
	Subnet  *net.IPNet
	Records []Record
	byName  map[string][]Record
}

func NewZoneView(name string, subnet *net.IPNet, records []Record) *ZoneView {
	zv := &ZoneView{
		Name:    name,
		Subnet:  subnet,
		Records: records,
		byName:  make(map[string][]Record),
	}
	for _, r := range records {
		n := r.DNSName()
		zv.byName[n] = append(zv.byName[n], r)
	}
	return zv
}

func (zv *ZoneView) Lookup(name string, qtype uint16) ([]Record, bool) {
	records, ok := zv.byName[name]
	if !ok {
		return nil, false
	}
	if qtype == dns.TypeANY {
		return records, true
	}
	if qtype == dns.TypeCNAME {
		for _, r := range records {
			if r.DNSType() == dns.TypeCNAME {
				return []Record{r}, true
			}
		}
		return nil, false
	}
	var matched []Record
	for _, r := range records {
		if r.DNSType() == qtype {
			matched = append(matched, r)
		}
	}
	return matched, len(matched) > 0
}

type Zone struct {
	Name       string
	Records    []Record
	DNSSEC     *DNSSECConfig
	SigningKey crypto.Signer
	Views      []*ZoneView

	byName map[string][]Record
}

func New(name string, records []Record, dnssec *DNSSECConfig, signingKey crypto.Signer, views []*ZoneView) *Zone {
	z := &Zone{
		Name:       name,
		Records:    records,
		DNSSEC:     dnssec,
		SigningKey: signingKey,
		Views:      views,
		byName:     make(map[string][]Record),
	}
	for _, r := range records {
		n := r.DNSName()
		z.byName[n] = append(z.byName[n], r)
	}
	return z
}

func (z *Zone) LookupInView(clientIP string, name string, qtype uint16) ([]Record, bool) {
	parsedIP := net.ParseIP(clientIP)
	if parsedIP == nil || len(z.Views) == 0 {
		return nil, false
	}
	for _, view := range z.Views {
		if view.Subnet != nil && view.Subnet.Contains(parsedIP) {
			return view.Lookup(name, qtype)
		}
	}
	return nil, false
}

func (z *Zone) Lookup(name string, qtype uint16) ([]Record, bool) {
	records, ok := z.byName[name]
	if !ok {
		return nil, false
	}
	if qtype == dns.TypeANY {
		return records, true
	}
	if qtype == dns.TypeCNAME {
		for _, r := range records {
			if r.DNSType() == dns.TypeCNAME {
				return []Record{r}, true
			}
		}
		return nil, false
	}
	var matched []Record
	for _, r := range records {
		if r.DNSType() == qtype {
			matched = append(matched, r)
		}
	}
	return matched, len(matched) > 0
}

func (z *Zone) LooksLikeAuthority(name string) bool {
	_, ok := z.byName[name]
	return ok
}

func (z *Zone) SOA() *SOARecord {
	for _, r := range z.byName[z.Name] {
		if soa, ok := r.(*SOARecord); ok {
			return soa
		}
	}
	return nil
}

func (z *Zone) NS() []*NSRecord {
	var result []*NSRecord
	for _, r := range z.byName[z.Name] {
		if ns, ok := r.(*NSRecord); ok {
			result = append(result, ns)
		}
	}
	return result
}

func expandName(name, zone string) string {
	if name == "@" {
		return zone
	}
	if name == "" {
		return zone
	}
	if name[len(name)-1] == '.' {
		return name
	}
	return name + "." + zone
}

func encodeName(name string) []byte {
	if name == "" || name == "." {
		return []byte{0}
	}
	name = trimDot(name)
	var buf []byte
	for _, label := range splitLabels(name) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	return append(buf, 0)
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func splitLabels(name string) []string {
	if name == "" {
		return nil
	}
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	return labels
}

func appendU32(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func binaryBigEndianPutUint16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func binaryBigEndianPutUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}
