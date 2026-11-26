// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"math"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// MaxDomains bounds the cluster domain list.
const MaxDomains = 128

// Domain is one registered cluster domain. It covers the name itself and
// every name below it; certificates link only to hosts inside one.
type Domain struct {
	Name    string // lower-case A-label, no trailing dot
	AddedBy string
	AddedAt int64
}

var domainProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.Transitional(false), idna.VerifyDNSLength(true))

// NormalizeDomain returns the A-label form of a registrable domain name, or
// the canonical form of an IP address, or false. Wildcards, single labels,
// public suffixes (the golang.org/x/net/publicsuffix list, such as com or
// co.kr), zoned, unspecified and multicast addresses are refused. An IP
// entry covers that address only, so IP-SAN certificates can link (a LAN
// registry reached by its address).
func NormalizeDomain(name string) (string, bool) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 || strings.ContainsAny(name, "*/ \t\r\n\x00") {
		return "", false
	}
	if a, err := netip.ParseAddr(name); err == nil {
		a = a.Unmap()
		if a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			return "", false
		}
		return a.String(), true
	}
	ascii, err := domainProfile.ToASCII(name)
	if err != nil || ascii == "" || !strings.Contains(ascii, ".") {
		return "", false
	}
	ascii = strings.ToLower(ascii)
	if suffix, _ := publicsuffix.PublicSuffix(ascii); suffix == ascii {
		return "", false
	}
	return ascii, true
}

// DisplayDomain is the Unicode form of an A-label for people to read.
func DisplayDomain(name string) string {
	u, err := idna.ToUnicode(name)
	if err != nil {
		return name
	}
	return u
}

// DomainCovers reports whether host (a DNS name, possibly *.wildcard) lies
// inside the registered domain. An IP host is covered only by the same IP.
func DomainCovers(domain, host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return host == domain
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return false
	}
	host = strings.ToLower(strings.TrimPrefix(host, "*."))
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func (c Catalog) validateDomains() error {
	if len(c.Domains) > MaxDomains {
		return ErrCertificate
	}
	last := ""
	for _, d := range c.Domains {
		if n, ok := NormalizeDomain(d.Name); !ok || n != d.Name || d.Name <= last || d.AddedBy == "" || len(d.AddedBy) > 128 || d.AddedAt <= 0 {
			return ErrCertificate
		}
		last = d.Name
	}
	return nil
}

// Domain returns the registered domain named name.
func (c Catalog) Domain(name string) (Domain, bool) {
	i := slices.IndexFunc(c.Domains, func(d Domain) bool { return d.Name == name })
	if i < 0 {
		return Domain{}, false
	}
	return c.Domains[i], true
}

// AddDomain registers an already normalized domain. expected is the
// catalog revision the caller read.
func (c Catalog) AddDomain(name, user string, expected uint64, at int64) (Catalog, error) {
	if c.Validate() != nil || expected != c.Revision || c.Revision == math.MaxUint64 || at <= 0 || user == "" || len(user) > 128 || len(c.Domains) >= MaxDomains {
		return c, ErrConflict
	}
	if n, ok := NormalizeDomain(name); !ok || n != name {
		return c, ErrCertificate
	}
	if _, exists := c.Domain(name); exists {
		return c, ErrConflict
	}
	next := c.Own()
	next.Domains = append(next.Domains, Domain{Name: name, AddedBy: user, AddedAt: at})
	slices.SortFunc(next.Domains, func(a, b Domain) int { return strings.Compare(a.Name, b.Name) })
	next.Revision++
	return next, nil
}

// RemoveDomain drops a registered domain. It is never refused for links:
// certificates under it only lose them.
func (c Catalog) RemoveDomain(name string, expected uint64) (Catalog, error) {
	if c.Validate() != nil || expected != c.Revision || c.Revision == math.MaxUint64 {
		return c, ErrConflict
	}
	if _, exists := c.Domain(name); !exists {
		return c, ErrConflict
	}
	next := c.Own()
	next.Domains = slices.DeleteFunc(next.Domains, func(d Domain) bool { return d.Name == name })
	if len(next.Domains) == 0 {
		next.Domains = nil
	}
	next.Revision++
	return next, nil
}
