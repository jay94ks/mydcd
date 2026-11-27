// SPDX-License-Identifier: Apache-2.0

package services

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// DNSRecord is a record a network's manager adds by hand. Unlike DNSName it
// carries its own value. Name is a full lower-case name ending in a dot;
// Value is the record's data in zone-file form, as miekg/dns prints it
// (an A's address, a CNAME's target "web.shop.internal.", an MX's
// "10 mail.example.org.", a TXT's "\"v=spf1 -all\""). TTL, when set, is
// the record's own TTL; the answer never exceeds the view's TTL (the cache
// TTL cap). Records of one name and type share one TTL.
//
// Registered (app) names come first: a hand record at a name an app service
// also has is kept in the policy but not served while that name is taken.
type DNSRecord struct {
	Name, Type, Value string
	TTL               uint32 `json:",omitempty"`
}

// DNSRecordTypes are the types a record may be added by hand as. PTR comes
// from the view's reverse zone; NS and SOA belong to the zone itself.
var DNSRecordTypes = []string{"A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA"}

const (
	// MaxDNSRecords is how many hand records one network's DNS keeps.
	MaxDNSRecords = 64
	// maxRecordSet is how many records one name may have of one type.
	maxRecordSet = 8
	// maxRecordValue bounds one record's data text (a TXT's strings are
	// also at most 255 bytes each).
	maxRecordValue = 1024
	// maxCNAMEChain is how many in-zone CNAMEs one answer follows.
	maxCNAMEChain = 8
)

// ParseDNSRecord reads r's data for its type and returns the record with
// Value in canonical form (names fully qualified, lower case where DNS
// ignores case). It does not check the record's place in a zone.
func ParseDNSRecord(r DNSRecord) (DNSRecord, dns.RR, error) {
	if !slices.Contains(DNSRecordTypes, r.Type) || r.Value == "" || len(r.Value) > maxRecordValue || strings.ContainsAny(r.Value, "\r\n\x00") || r.TTL > 3600 {
		return r, nil, ErrProtocol
	}
	name, err := Domain(r.Name)
	if err != nil {
		return r, nil, err
	}
	rr, err := dns.NewRR(name + " 1 IN " + r.Type + " " + r.Value)
	if err != nil || rr == nil || dns.TypeToString[rr.Header().Rrtype] != r.Type || rr.Header().Name != name {
		return r, nil, ErrProtocol
	}
	switch v := rr.(type) {
	case *dns.A:
		a, ok := netip.AddrFromSlice(v.A)
		a = a.Unmap()
		if !ok || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return r, nil, ErrProtocol
		}
	case *dns.AAAA:
		a, ok := netip.AddrFromSlice(v.AAAA)
		if !ok || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() {
			return r, nil, ErrProtocol
		}
	case *dns.CNAME:
		if v.Target, err = Domain(v.Target); err != nil || v.Target == name {
			return r, nil, ErrProtocol
		}
	case *dns.MX:
		if v.Mx, err = Domain(v.Mx); err != nil {
			return r, nil, ErrProtocol
		}
	case *dns.SRV:
		if v.Target, err = Domain(v.Target); err != nil {
			return r, nil, ErrProtocol
		}
	case *dns.TXT:
		if len(v.Txt) < 1 || len(v.Txt) > 16 {
			return r, nil, ErrProtocol
		}
	case *dns.CAA:
		v.Tag = strings.ToLower(v.Tag)
		if v.Flag != 0 && v.Flag != 128 || v.Tag != "issue" && v.Tag != "issuewild" && v.Tag != "iodef" || len(v.Value) > 255 {
			return r, nil, ErrProtocol
		}
	}
	r.Name = name
	r.Value = strings.TrimPrefix(rr.String(), rr.Header().String())
	return r, rr, nil
}

// ValidDNSRecords checks hand records for zone (and the zone's separate
// client zone, if any) and returns them sorted. A name with a CNAME has
// nothing else; one name has at most 8 records of a type, all with one
// TTL; no record sits at ns.<zone> or in the client zone, and the zone
// itself has no CNAME. Records must already be canonical (ParseDNSRecord).
func ValidDNSRecords(zone, clientZone string, records []DNSRecord) ([]DNSRecord, error) {
	if len(records) > MaxDNSRecords {
		return nil, ErrProtocol
	}
	out := slices.Clone(records)
	types := map[string]map[string]bool{}
	count := map[string]int{}
	ttls := map[string]uint32{}
	seen := map[string]bool{}
	for _, r := range out {
		name, err := canonicalName(r.Name, zone)
		if r.Name == zone && r.Type != "CNAME" {
			name, err = zone, nil // the zone's own MX, TXT, CAA, address
		}
		if err != nil || name != r.Name || !strings.HasSuffix(r.Name, ".") || clientZone != "" && dns.IsSubDomain(clientZone, name) {
			return nil, ErrProtocol
		}
		canonical, _, err := ParseDNSRecord(r)
		if err != nil || canonical != r {
			return nil, ErrProtocol
		}
		key := r.Name + "\x00" + r.Type + "\x00" + r.Value
		set := r.Name + "\x00" + r.Type
		if seen[key] {
			return nil, ErrProtocol
		}
		seen[key] = true
		if types[name] == nil {
			types[name] = map[string]bool{}
		}
		types[name][r.Type] = true
		if types[name]["CNAME"] && len(types[name]) > 1 {
			return nil, ErrProtocol
		}
		if count[set]++; count[set] > maxRecordSet || r.Type == "CNAME" && count[set] > 1 {
			return nil, ErrProtocol
		}
		if ttl, ok := ttls[set]; ok && ttl != r.TTL {
			return nil, ErrProtocol
		}
		ttls[set] = r.TTL
	}
	sortDNSRecords(out)
	return out, nil
}

func sortDNSRecords(records []DNSRecord) {
	slices.SortFunc(records, func(a, b DNSRecord) int {
		return strings.Compare(a.Name+"\x00"+a.Type+"\x00"+a.Value, b.Name+"\x00"+b.Type+"\x00"+b.Value)
	})
}

// splitDNSRecords returns the hand records to serve (those whose name no
// registered name has) and the ones that wait for the name to be free.
func splitDNSRecords(records []DNSRecord, names []DNSName) (served, shadowed []DNSRecord) {
	taken := map[string]bool{}
	for _, n := range names {
		taken[n.Name] = true
	}
	served, shadowed = []DNSRecord{}, []DNSRecord{}
	for _, r := range records {
		if taken[r.Name] {
			shadowed = append(shadowed, r)
		} else {
			served = append(served, r)
		}
	}
	return served, shadowed
}

// policyRecords is the policy's hand records checked for its zone.
func (d ManagedDNSDefinition) policyRecords(zone string) ([]DNSRecord, error) {
	clientZone := ""
	if d.Policy.ClientZone != "" {
		z, err := Domain(d.Policy.ClientZone)
		if err != nil {
			return nil, err
		}
		clientZone = z
	}
	return ValidDNSRecords(zone, clientZone, d.Policy.Records)
}

// Records is the policy's hand records for reading back: the ones served
// and the ones not served because a registered name has their name.
func (d ManagedDNSDefinition) Records(registrations []DNSRegistration) (served, shadowed []DNSRecord, err error) {
	zone, err := Domain(d.Policy.Zone)
	if err != nil {
		return nil, nil, err
	}
	records, err := d.policyRecords(zone)
	if err != nil {
		return nil, nil, err
	}
	names, err := d.registrationNames(zone, registrations)
	if err != nil {
		return nil, nil, err
	}
	served, shadowed = splitDNSRecords(records, names)
	return served, shadowed, nil
}

// validConfigRecords checks a view's hand records: canonical, sorted, and at
// no name the view's registered records have.
func validConfigRecords(c DNSConfig, names []string) bool {
	records, err := ValidDNSRecords(c.Zone, c.ClientZone, c.Records)
	if err != nil || !slices.Equal(records, c.Records) {
		return false
	}
	taken := map[string]bool{}
	for _, n := range names {
		taken[n] = true
	}
	for _, r := range c.Records {
		if taken[r.Name] {
			return false
		}
	}
	return true
}

// MoveDNSRecords renames records from zone old to zone: their names and the
// CNAME, MX and SRV targets inside old. The result is checked for zone.
func MoveDNSRecords(records []DNSRecord, old, zone, clientZone string) ([]DNSRecord, error) {
	move := func(name string) string {
		if dns.IsSubDomain(old, name) {
			return strings.TrimSuffix(name, old) + zone
		}
		return name
	}
	out := make([]DNSRecord, 0, len(records))
	for _, r := range records {
		_, rr, err := ParseDNSRecord(r)
		if err != nil {
			return nil, err
		}
		switch v := rr.(type) {
		case *dns.CNAME:
			v.Target = move(v.Target)
		case *dns.MX:
			v.Mx = move(v.Mx)
		case *dns.SRV:
			v.Target = move(v.Target)
		}
		r.Name = move(r.Name)
		r.Value = strings.TrimPrefix(rr.String(), rr.Header().String())
		out = append(out, r)
	}
	return ValidDNSRecords(zone, clientZone, out)
}
