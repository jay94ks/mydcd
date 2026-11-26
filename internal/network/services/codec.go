// SPDX-License-Identifier: Apache-2.0

// Package services is the network module's embedded DNS boundary. Wire
// parsing uses upstream libraries; owner/IPAM/quorum and durable query
// authorization remain separate product contracts. Decoding grants no address.
package services

import (
	"errors"
	"strings"

	"github.com/miekg/dns"
)

var ErrProtocol = errors.New("unsupported or invalid network service message")

func Domain(s string) (string, error) {
	if s == "" || strings.ContainsAny(s, "\\\x00\r\n") {
		return "", ErrProtocol
	}
	s = strings.ToLower(dns.Fqdn(s))
	if _, ok := dns.IsDomainName(s); !ok || s == "." {
		return "", ErrProtocol
	}
	return s, nil
}

func DecodeDNSQuery(raw []byte, limit int) (*dns.Msg, error) {
	if limit < 12 || limit > 65535 || len(raw) < 12 || len(raw) > limit {
		return nil, ErrProtocol
	}
	m := new(dns.Msg)
	if m.Unpack(raw) != nil || m.Response || m.Opcode != dns.OpcodeQuery || len(m.Question) != 1 || len(m.Answer) != 0 || len(m.Ns) != 0 || len(m.Extra) > 1 {
		return nil, ErrProtocol
	}
	q := m.Question[0]
	name, err := Domain(q.Name)
	if err != nil || q.Qclass != dns.ClassINET || q.Qtype == dns.TypeANY || q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		return nil, ErrProtocol
	}
	if len(m.Extra) == 1 {
		opt, ok := m.Extra[0].(*dns.OPT)
		if !ok || opt.Hdr.Name != "." || opt.Version() != 0 || len(opt.Option) != 0 {
			return nil, ErrProtocol
		}
	}
	m.Question[0].Name = name
	return m, nil
}
