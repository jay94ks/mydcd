// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"math"
	"net/netip"
)

// ACMEResponder is the cluster's HTTP-01 responder address (sfc-web's
// acme-listen, inside the TUN network). Ingress forwards
// /.well-known/acme-challenge/ of registered-domain hosts on its clear
// listeners there; without one that path answers 404.
type ACMEResponder struct {
	Address string // canonical IP:port
	SetBy   string
	SetAt   int64
}

// NormalizeResponder returns the canonical IP:port of a responder address or
// false. A host name, port 0, zone, unspecified and multicast addresses are
// refused.
func NormalizeResponder(address string) (string, bool) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || ap.Port() == 0 {
		return "", false
	}
	a := ap.Addr().Unmap()
	if a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
		return "", false
	}
	return netip.AddrPortFrom(a, ap.Port()).String(), true
}

func (r *ACMEResponder) valid() bool {
	if r == nil {
		return true
	}
	n, ok := NormalizeResponder(r.Address)
	return ok && n == r.Address && r.SetBy != "" && len(r.SetBy) <= 128 && r.SetAt > 0
}

// SetACMEResponder sets (or, with an empty address, clears) the responder
// under the catalog revision CAS. Setting the same address again is a
// conflict so a repeated start of sfc-web does not bump the revision.
func (c Catalog) SetACMEResponder(address, user string, expected uint64, at int64) (Catalog, error) {
	if c.Validate() != nil || expected != c.Revision || c.Revision == math.MaxUint64 || at <= 0 || user == "" || len(user) > 128 {
		return c, ErrConflict
	}
	next := c.Own()
	if address == "" {
		if c.ACMEResponder == nil {
			return c, ErrConflict
		}
		next.ACMEResponder = nil
	} else {
		n, ok := NormalizeResponder(address)
		if !ok || n != address {
			return c, ErrCertificate
		}
		if c.ACMEResponder != nil && c.ACMEResponder.Address == address {
			return c, ErrConflict
		}
		next.ACMEResponder = &ACMEResponder{Address: address, SetBy: user, SetAt: at}
	}
	next.Revision++
	return next, nil
}
