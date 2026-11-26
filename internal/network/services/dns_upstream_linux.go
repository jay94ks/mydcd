// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// The library owns DNS coding; the adapter owns byte bounds and FD lifetime.
// dns.Client's TCP reader allocates the advertised length before our policy
// validation, so use the same bounded frame reader as the native server.
func exchangeDNSUpstream(ctx context.Context, peer netip.AddrPort, request *dns.Msg, tcp bool, limit int) (*dns.Msg, error) {
	if !peer.IsValid() || request == nil || limit < 512 || limit > 65535 {
		return nil, ErrProtocol
	}
	protocol := "udp"
	if tcp {
		protocol = "tcp"
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, protocol, peer.String())
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		_ = conn.Close()
	}()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		return nil, ErrProtocol
	}
	co := &dns.Conn{Conn: conn, UDPSize: uint16(limit)}
	if err = co.WriteMsg(request); err != nil {
		return nil, err
	}
	var raw []byte
	if tcp {
		raw, err = ReadDNSTCPFrame(conn, limit)
	} else {
		raw = make([]byte, limit+1)
		var n int
		n, err = conn.Read(raw)
		raw = raw[:n]
		if len(raw) > limit {
			return nil, ErrProtocol
		}
	}
	if err != nil {
		return nil, err
	}
	response := new(dns.Msg)
	if response.Unpack(raw) != nil || !response.Response || response.Opcode != dns.OpcodeQuery || response.Id != request.Id || len(response.Question) != 1 || response.Question[0].Qtype != request.Question[0].Qtype || response.Question[0].Qclass != request.Question[0].Qclass {
		return nil, ErrProtocol
	}
	name, e := Domain(response.Question[0].Name)
	if e != nil || name != request.Question[0].Name {
		return nil, ErrProtocol
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ctx.Err(), ErrProtocol)
	}
	return response, nil
}
