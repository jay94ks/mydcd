// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
)

func TestInstalledAckRelayRequiresCurrentControlAndTargetProof(t *testing.T) {
	a := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, 32))
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))
	foreign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{43}, 32))
	public := func(k ed25519.PrivateKey) [32]byte {
		var p [32]byte
		copy(p[:], k.Public().(ed25519.PublicKey))
		return p
	}
	genesis := config.Peer{ID: "source", Key: hex.EncodeToString(a.Public().(ed25519.PublicKey)), Endpoint: "127.0.0.1:8001", Voter: true}
	target := config.Peer{ID: "target", Key: hex.EncodeToString(b.Public().(ed25519.PublicKey)), Endpoint: "127.0.0.1:8002"}
	p := Policy{Cluster: [32]byte{71}, BootstrapKey: [32]byte{72}, TrustRoot: public(a), Genesis: genesis}
	d, _ := membership.New(p.Cluster, genesis)
	d, _ = d.Invite(target, "join-target", nil)
	entry, _ := d.Entry(target.ID)
	d, err := d.Dispatch(target.ID, entry.Revision, entry.Job.Pending.ID, 1, public(a))
	if err != nil {
		t.Fatal(err)
	}
	entry, _ = d.Entry(target.ID)
	d, err = d.Observe(target.ID, entry.Revision, entry.Job.Pending.ID, 4, target)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ = d.Entry(target.ID)
	original := membership.Ack{Schema: 1, Cluster: p.Cluster, Node: target.ID, JoinID: entry.JoinID, Key: public(b), ConfigurationIndex: 4, AppliedIndex: 5}
	original.Signature = ed25519.Sign(b, membership.AckBytes(original))
	s, _ := state.New("admin")
	writes, code := p.memberCheckpoint(s, d)
	if code != state.Applied {
		t.Fatal(code)
	}
	s, _, err = state.ApplyReduced(s, 1, state.Command{Kind: state.Module, Actor: "admin", Epoch: 1, RequestID: "fixture", Key: MembersKey, Value: "fixed"}, p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		key    ed25519.PrivateKey
		mutate func(*membership.Ack)
		want   state.Code
	}{
		{"installed control relay", a, nil, state.Applied},
		{"target direct report", b, nil, state.Applied},
		{"unapproved relay", foreign, nil, state.Forbidden},
		{"wrong target signature", a, func(ack *membership.Ack) { ack.Signature = ed25519.Sign(a, membership.AckBytes(*ack)) }, state.ConditionFailed},
		{"foreign cluster", a, func(ack *membership.Ack) {
			ack.Cluster = [32]byte{99}
			ack.Signature = ed25519.Sign(b, membership.AckBytes(*ack))
		}, state.ConditionFailed},
		{"wrong target", a, func(ack *membership.Ack) {
			ack.Node = "other"
			ack.Signature = ed25519.Sign(b, membership.AckBytes(*ack))
		}, state.Forbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			ack := original
			if test.mutate != nil {
				test.mutate(&ack)
			}
			report := MemberReport{Schema: 1, Cluster: p.Cluster, Reporter: public(test.key), Action: "installed", Node: target.ID, Expected: entry.Revision, Ack: &ack, Epoch: 1, RequestID: "install", RootRevision: s.Object(MembersKey).Revision}
			report.Signature = ed25519.Sign(test.key, MemberReportBytes(report))
			cmd, err := report.Command()
			if err != nil {
				t.Fatal(err)
			}
			next, result, err := state.ApplyAdmitted(s, 2, cmd, p.Validate, p.Reduce, p.AdmitModule)
			if err != nil || result.Code != test.want {
				t.Fatal("ACK authority", result, err)
			}
			after, err := p.Members(next)
			if err != nil {
				t.Fatal(err)
			}
			observed, _ := after.Entry(target.ID)
			if result.Code == state.Applied {
				if observed.Phase != membership.Ready {
					t.Fatal("ACK not installed")
				}
			} else if observed.Phase != membership.Learner {
				t.Fatal("invalid ACK changed membership")
			}
		})
	}
}
