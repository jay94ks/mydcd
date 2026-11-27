// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/observability"
)

// Consume the actual SDK/FSM observation, not an invented counter tuple. The
// same validator/signing bytes are used by the node's periodic publisher.
func TestConsensusObservationProducesValidSignedReportAfterSnapshot(t *testing.T) {
	f := newControlBoundary(t)
	f.enroll()
	check := func(stage string) {
		t.Helper()
		v := f.view()
		c, err := f.engine.ConsensusObservation(f.ctx)
		if err != nil {
			t.Fatal(stage, err)
		}
		r := observability.Report{Kind: "node-observation", Schema: 1, Cluster: f.policy.Cluster, Node: f.engine.ObservedNodeID(), Key: f.node.Public, Index: v.State.Index(), At: uint64(time.Now().UnixMilli()), Consensus: &c}
		r.Signature = ed25519.Sign(f.node.Private, observability.SigningBytes(r))
		if !r.Valid() {
			t.Fatalf("%s actual SDK observation rejected at=%d index=%d node=%s consensus=%+v", stage, r.At, r.Index, r.Node, c)
		}
	}
	check("before snapshot")
	if err := f.engine.Snapshot(f.ctx); err != nil {
		t.Fatal(err)
	}
	check("after snapshot")
}

func TestConsensusObservationWaitsForLiveCommitAfterOriginalFSMReopen(t *testing.T) {
	f := newControlBoundary(t)
	f.enroll()
	before := f.view()
	f.close()
	f.startUnready()
	published := f.engine.fsm.readView.Load()
	if published == nil || published.index == 0 || f.engine.raft.CommitIndex() != 0 {
		t.Fatal("test did not reach the actual reopened durable/live boundary")
	}
	if c, err := f.engine.ConsensusObservation(f.ctx); !errors.Is(err, ErrRecovering) {
		t.Fatal("reopened FSM/live counters published an incoherent report", c, err)
	}
	f.wait(func() bool {
		_, err := f.engine.Read(f.ctx, true)
		return err == nil
	})
	v := f.view()
	if v.State.Index() != before.State.Index() {
		t.Fatal("observation recovery changed original committed state")
	}
	c, err := f.engine.ConsensusObservation(f.ctx)
	if err != nil {
		t.Fatal("actual quorum recovered but consensus observation did not", err)
	}
	r := observability.Report{Kind: "node-observation", Schema: 1, Cluster: f.policy.Cluster, Node: f.engine.ObservedNodeID(), Key: f.node.Public, Index: v.State.Index(), At: uint64(time.Now().UnixMilli()), Consensus: &c}
	r.Signature = ed25519.Sign(f.node.Private, observability.SigningBytes(r))
	if !r.Valid() {
		t.Fatal("recovered actual SDK consensus cannot publish signed observation", c)
	}
}
