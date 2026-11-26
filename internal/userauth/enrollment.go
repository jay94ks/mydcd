// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func EnrollmentBytes(cluster, key, challenge [32]byte, body []byte) []byte {
	b := append([]byte("mydc-admin-enrollment-1\x00"), cluster[:]...)
	b = append(b, key[:]...)
	b = append(b, challenge[:]...)
	return append(b, body...)
}

func (c Client) Enroll(ctx context.Context, target mydcp.Peer, intent control.Enrollment, private ed25519.PrivateKey) (Reply, error) {
	if c.Self == nil || len(private) != ed25519.PrivateKeySize {
		return Reply{}, mydcp.ErrAdmission
	}
	var anchor [32]byte
	copy(anchor[:], private.Public().(ed25519.PublicKey))
	if _, err := intent.Command(anchor); err != nil {
		return Reply{}, err
	}
	body, err := requestBody(Request{Method: "enroll-admin", UserKey: anchor, Enrollment: &intent})
	if err != nil {
		return Reply{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(conn *mydcp.Session) (Envelope, error) {
		return Envelope{Body: body, Signature: ed25519.Sign(private, EnrollmentBytes(c.Cluster, c.Self.Public, conn.PeerChallenge(), body))}, nil
	}, true)
	return reply, err
}

func (s Service) enroll(ctx context.Context, view cluster.View, c access.Catalog, binding userBinding, r Request, envelope Envelope) Reply {
	reply := Reply{Schema: 1, Code: "denied"}
	if r.Enrollment == nil || envelope.Session != nil || envelope.Relay != nil || r.Operation != nil || r.Username != "" || r.Tenant != "" || r.After != "" || r.Node != "" || r.Proof != nil || r.Ticket != nil || r.UserKey != s.Policy.BootstrapKey || !ed25519.Verify(ed25519.PublicKey(s.Policy.BootstrapKey[:]), EnrollmentBytes(s.Policy.Cluster, binding.key, binding.challenge, envelope.Body), envelope.Signature) {
		return reply
	}
	command, err := r.Enrollment.Command(s.Policy.BootstrapKey)
	if err != nil {
		return reply
	}
	if result, found := view.State.LookupResult(command); found {
		return Reply{Schema: 1, Code: "ok", Result: &result, Found: true}
	}
	if !c.AwaitingAdmin() {
		return reply
	}
	committed, err := s.Engine.Submit(ctx, command)
	if err != nil {
		reply.Code = "unavailable"
		if errors.Is(err, cluster.ErrUnknown) {
			reply.Code = "unknown"
		}
		return reply
	}
	return Reply{Schema: 1, Code: "ok", Result: &committed.Result, Found: true, RootRevision: committed.Result.Revision}
}
