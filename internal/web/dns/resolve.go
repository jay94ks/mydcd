// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// Resolver asks one DNS server for one name and type (the propagation
// check). The web app does this itself; sfcd is not involved.
type Resolver interface {
	// Query sends a single question to server (host:port). recurse sets RD:
	// true for a public resolver, false for an authoritative server.
	Query(ctx context.Context, server, fqdn, rtype string, recurse bool) (Answer, error)
}

// Answer is the values of the answer section, in Values form, and the
// smallest TTL among them.
type Answer struct {
	Values []string
	TTL    uint32
}

// PublicResolvers are the public resolvers the propagation check asks.
var PublicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// NetResolver queries over the network (UDP, then TCP when truncated).
type NetResolver struct{ Timeout time.Duration }

func (n NetResolver) Query(ctx context.Context, server, fqdn, rtype string, recurse bool) (Answer, error) {
	t, ok := mdns.StringToType[strings.ToUpper(rtype)]
	if !ok {
		return Answer{}, &Error{Kind: Invalid, Detail: "record type " + rtype}
	}
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(fqdn), t)
	m.RecursionDesired = recurse
	timeout := n.Timeout
	if timeout == 0 {
		timeout = 4 * time.Second
	}
	c := &mdns.Client{Timeout: timeout}
	in, _, err := c.ExchangeContext(ctx, m, server)
	if err == nil && in.Truncated {
		c.Net = "tcp"
		in, _, err = c.ExchangeContext(ctx, m, server)
	}
	if err != nil {
		return Answer{}, &Error{Kind: Unavailable, Detail: err.Error()}
	}
	if in.Rcode != mdns.RcodeSuccess && in.Rcode != mdns.RcodeNameError {
		return Answer{}, &Error{Kind: Unavailable, Detail: mdns.RcodeToString[in.Rcode]}
	}
	var a Answer
	for _, rr := range in.Answer {
		if rr.Header().Rrtype != t {
			continue
		}
		if a.TTL == 0 || rr.Header().Ttl < a.TTL {
			a.TTL = rr.Header().Ttl
		}
		a.Values = append(a.Values, answerValue(rr))
	}
	return a, nil
}

// answerValue writes an answer record like a zone record's text: the
// content, with "priority content" for MX and SRV.
func answerValue(rr mdns.RR) string {
	switch v := rr.(type) {
	case *mdns.A:
		return v.A.String()
	case *mdns.AAAA:
		return v.AAAA.String()
	case *mdns.CNAME:
		return trimDot(v.Target)
	case *mdns.NS:
		return trimDot(v.Ns)
	case *mdns.MX:
		return strconv.Itoa(int(v.Preference)) + " " + trimDot(v.Mx)
	case *mdns.TXT:
		return strings.Join(v.Txt, "")
	case *mdns.CAA:
		return strconv.Itoa(int(v.Flag)) + " " + v.Tag + " \"" + v.Value + "\""
	case *mdns.SRV:
		return strconv.Itoa(int(v.Priority)) + " " + strconv.Itoa(int(v.Weight)) + " " + strconv.Itoa(int(v.Port)) + " " + trimDot(v.Target)
	}
	parts := strings.SplitN(rr.String(), "\t", 5)
	return parts[len(parts)-1]
}

func trimDot(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

// WantValues is a zone set's records in Answer form, for comparison.
func WantValues(r *RRSet) []string {
	if r == nil {
		return []string{}
	}
	out := make([]string, 0, len(r.Records))
	for _, v := range r.Records {
		c := v.Content
		if r.Type == "CNAME" || r.Type == "NS" || r.Type == "MX" || r.Type == "SRV" {
			c = trimDot(c)
		}
		if v.Priority != 0 || r.Type == "MX" {
			c = strconv.Itoa(v.Priority) + " " + c
		}
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// SameValues compares two value lists as sets (TXT and IPs exactly, names
// without case or trailing dot).
func SameValues(a, b []string) bool {
	norm := func(v []string) []string {
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = strings.TrimSuffix(strings.TrimSpace(s), ".")
			if ip := net.ParseIP(out[i]); ip != nil {
				out[i] = ip.String()
			}
		}
		sort.Strings(out)
		return out
	}
	x, y := norm(a), norm(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
