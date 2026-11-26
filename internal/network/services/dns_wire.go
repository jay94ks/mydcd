// SPDX-License-Identifier: Apache-2.0

package services

import (
	"encoding/binary"
	"io"

	"github.com/miekg/dns"
)

// EncodeDNSReply is the one transport encoder. The original cache/view is
// immutable; UDP truncation and EDNS are per-request, never cached metadata.
func EncodeDNSReply(raw []byte, response *dns.Msg, tcp bool, limit int) ([]byte, error) {
	request, err := DecodeDNSQuery(raw, 4096)
	if err != nil || response == nil || limit < 512 || limit > 65535 || !response.Response || response.Id != request.Id {
		return nil, ErrProtocol
	}
	q := response.Copy()
	q.Extra = nil
	maximum := limit
	if !tcp {
		maximum = min(maximum, 512)
	}
	if opt := request.IsEdns0(); opt != nil {
		if !tcp {
			maximum = min(limit, max(512, int(opt.UDPSize())))
		}
		q.SetEdns0(uint16(limit), false)
	}
	if !tcp {
		// The configured DNS message limit also serves TCP. An IPv4 UDP
		// payload must fit beneath its 65535-byte IP total length, including
		// the 20-byte IP and 8-byte UDP headers, even with oversized EDNS.
		maximum = min(maximum, 65507)
	}
	q.Truncate(maximum)
	q.Compress = true
	wire, err := q.Pack()
	if err != nil || len(wire) > maximum {
		return nil, ErrProtocol
	}
	return wire, nil
}

// ReadDNSTCPFrame validates the peer's length BEFORE allocating its body. The
// same framing contract is used by both the native server and upstream client.
func ReadDNSTCPFrame(r io.Reader, limit int) ([]byte, error) {
	if limit < 12 || limit > 65535 {
		return nil, ErrProtocol
	}
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n < 12 || n > limit {
		return nil, ErrProtocol
	}
	raw := make([]byte, n)
	_, err := io.ReadFull(r, raw)
	return raw, err
}
