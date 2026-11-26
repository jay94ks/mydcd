// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

var errRouteDNSTimeout = errors.New("route DNS socket timed out")

// A real DNS question from the nonroot workload, not an echo payload sent to
// port 53. Exit 2 is reserved for timeout, so malformed replies/configuration
// cannot satisfy the fixture's isolation predicate.
func routeDNSProbe(args []string) error {
	if len(args) != 3 || args[0] != "udp" && args[0] != "tcp" {
		return fmt.Errorf("route DNS requires udp|tcp, numeric gateway:53 and zone")
	}
	server, err := netip.ParseAddrPort(args[1])
	if err != nil || server.Port() != 53 || server.Addr().IsUnspecified() || server.Addr().IsMulticast() {
		return fmt.Errorf("invalid route DNS gateway")
	}
	zone := dns.Fqdn(args[2])
	if _, ok := dns.IsDomainName(zone); !ok {
		return fmt.Errorf("invalid route DNS zone")
	}
	query := new(dns.Msg)
	query.SetQuestion(zone, dns.TypeSOA)
	query.RecursionDesired = false
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := dns.Client{Net: args[0], Timeout: 3 * time.Second}
	answer, _, err := client.ExchangeContext(ctx, query, server.String())
	if err != nil {
		var networkError net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout() {
			return fmt.Errorf("%w: %v", errRouteDNSTimeout, err)
		}
		return err
	}
	if err := validateRouteDNSResponse(query, answer); err != nil {
		return err
	}
	fmt.Println("route DNS SOA verified", args[0], server, zone)
	return nil
}

func validateRouteDNSResponse(query, answer *dns.Msg) error {
	if query == nil || answer == nil || !answer.Response || !answer.Authoritative || answer.Truncated || answer.Id != query.Id || answer.Rcode != dns.RcodeSuccess || len(query.Question) != 1 || len(answer.Question) != 1 || answer.Question[0] != query.Question[0] || len(answer.Answer) != 1 {
		return fmt.Errorf("invalid authoritative route DNS response")
	}
	soa, ok := answer.Answer[0].(*dns.SOA)
	if !ok || soa.Hdr.Name != query.Question[0].Name || soa.Hdr.Class != dns.ClassINET || soa.Hdr.Rrtype != dns.TypeSOA {
		return fmt.Errorf("route DNS SOA differs from requested zone")
	}
	return nil
}
