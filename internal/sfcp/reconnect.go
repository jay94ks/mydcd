// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"

	"github.com/jay94ks/seafield/internal/observability"
)

type ReconnectResult struct {
	PairID, State string
	HandshakeAt   uint64
	KeptExisting  bool
}

// ReconnectBrokenMember never closes a live connection. Caller owns the
// accepted user intent and fresh quorum grant; transport still validates the
// current installed member and authenticated handshake at its normal boundary.
func (t *Transport) ReconnectBrokenMember(ctx context.Context, local string, peer Peer) (ReconnectResult, error) {
	var out ReconnectResult
	current, known := t.lookupFor(peer.Key, Handshake)
	if !known || !current.Member || !current.Report || current.ID != peer.ID || current.Endpoint != peer.Endpoint || peer.Key == t.LocalKey() || local == "" || local == peer.ID {
		return out, ErrAdmission
	}
	link, observed := t.LinkObservation(local, current)
	if !observed {
		return out, ErrAdmission
	}
	out.PairID = observability.PairID(local, current.ID)
	if link.State != "down" {
		out.State, out.HandshakeAt, out.KeptExisting = "already-connected", link.LastHandshakeAt, true
		return out, nil
	}
	if _, err := t.Dial(ctx, current); err != nil {
		return out, err
	}
	link, observed = t.LinkObservation(local, current)
	if !observed || link.State == "down" || link.LastHandshakeAt == 0 {
		return out, ErrAdmission
	}
	out.State, out.HandshakeAt = "reconnected", link.LastHandshakeAt
	return out, nil
}
