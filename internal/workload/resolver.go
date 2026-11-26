// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// Resolver freezes explicit Docker resolver inputs. A nil ContainerSpec field
// preserves the existing unspecified resolver contract. An explicit empty
// resolver suppresses managed DNS injection and follows Docker's defaults.
type Resolver struct {
	Servers []netip.Addr
	Search  []string
}

func (r Resolver) Validate() error {
	if len(r.Servers) > 4 || len(r.Search) > 6 {
		return ErrPlacement
	}
	for _, a := range r.Servers {
		if !a.IsValid() || a.Is4In6() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			return ErrPlacement
		}
	}
	for _, s := range r.Search {
		if s == "" || len(s) > 253 || strings.ContainsAny(s, "\\\x00\r\n\t ") {
			return ErrPlacement
		}
		if _, valid := dns.IsDomainName(s); !valid {
			return ErrPlacement
		}
	}
	return nil
}
