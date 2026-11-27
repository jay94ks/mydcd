// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/identity"
)

// Both ends announce their feature sets in the handshake; a purpose/kind that
// needs a feature is sent only when both ends have it, and the cluster set is
// the in-memory intersection over each member's last announced set.
func TestFeatureSetsGateSendingAndIntersect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	transit := buildinfo.Features(0).With(buildinfo.FeatureTransit)
	spec := purposes[Observation]
	saved := spec.kindNeeds
	spec.kindNeeds = map[uint8]buildinfo.Features{KindWorkloadReport: transit}
	purposes[Observation] = spec
	defer func() { spec.kindNeeds = saved; purposes[Observation] = spec }()

	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	peers := map[Identity]Peer{Identity(a.Public): {ID: "sender", Policy: Policy{Key: Identity(a.Public), Member: true, Report: true}}, Identity(b.Public): {ID: "receiver", Policy: Policy{Key: Identity(b.Public), Member: true, Respond: true}}}
	var mu sync.RWMutex
	lookup := func(key Identity) (Peer, bool) { mu.RLock(); defer mu.RUnlock(); p, ok := peers[key]; return p, ok }
	receiver, err := NewTransport(b, [32]byte{1}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	receiver.own = transit
	if err = receiver.OnReport(func(context.Context, *Session, uint8, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = receiver.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	target := peers[Identity(b.Public)]
	target.Endpoint = receiver.Addr().String()
	peers[target.Key] = target
	mu.Unlock()

	dial := func(own buildinfo.Features) (*Transport, *Session) {
		sender, err := NewTransport(a, [32]byte{1}, lookup)
		if err != nil {
			t.Fatal(err)
		}
		sender.own = own
		s, err := sender.Dial(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		return sender, s
	}

	// A baseline sender: nothing needing transit leaves it.
	old, s := dial(0)
	if s.PeerFeatures() != transit || s.Supports(Observation, KindWorkloadReport) || !s.Supports(Observation, KindNodeObservation) {
		t.Fatal("baseline sender support", s.PeerFeatures())
	}
	if err = s.Report(ctx, KindWorkloadReport, []byte("x")); !errors.Is(err, ErrUnsupported) {
		t.Fatal("unsupported kind sent", err)
	}
	if err = s.Report(ctx, KindNodeObservation, []byte("x")); err != nil {
		t.Fatal("baseline kind", err)
	}
	waitFor(t, func() bool {
		f, live := receiver.PeerFeatures(Identity(a.Public))
		return live && f == 0
	})
	members := []Identity{Identity(a.Public), Identity(b.Public)}
	if got := receiver.ClusterFeatures(members); got != 0 {
		t.Fatal("intersection with a baseline member", got)
	}
	old.Close()
	waitFor(t, func() bool { _, live := receiver.PeerFeatures(Identity(a.Public)); return !live })
	// Away, it still counts with the set it last announced.
	if got := receiver.ClusterFeatures(members); got != 0 {
		t.Fatal("away baseline member", got)
	}

	// A transit sender: both ends have it.
	sender, s := dial(transit)
	defer sender.Close()
	if !s.Supports(Observation, KindWorkloadReport) {
		t.Fatal("both ends have transit")
	}
	if err = s.Report(ctx, KindWorkloadReport, []byte("x")); err != nil {
		t.Fatal("supported kind", err)
	}
	waitFor(t, func() bool { return receiver.ClusterFeatures(members) == transit })
	// A member never seen since this process started counts as empty.
	var unseen Identity
	unseen[0] = 9
	if got := receiver.ClusterFeatures(append(members, unseen)); got != 0 {
		t.Fatal("never-seen member kept a feature on", got)
	}
	// A disconnected member keeps the set it last announced.
	sender.Close()
	waitFor(t, func() bool { _, live := receiver.PeerFeatures(Identity(a.Public)); return !live })
	if got := receiver.ClusterFeatures(members); got != transit {
		t.Fatal("disconnected member's last set", got)
	}
}

// A peer that did not announce a needed feature has its frames refused.
func TestGateRefusesFramesNeedingUnannouncedFeatures(t *testing.T) {
	transit := buildinfo.Features(0).With(buildinfo.FeatureTransit)
	spec := purposes[Observation]
	saved := spec.kindNeeds
	spec.kindNeeds = map[uint8]buildinfo.Features{KindWorkloadReport: transit}
	purposes[Observation] = spec
	defer func() { spec.kindNeeds = saved; purposes[Observation] = spec }()
	key := Identity{7}
	f := Frame{Purpose: Observation, Kind: KindWorkloadReport, Request: 1, Fields: []Field{{Tag: 1, Required: true, Value: []byte("x")}}}
	for _, c := range []struct {
		peer, own buildinfo.Features
		ok        bool
	}{{0, transit, false}, {transit, 0, false}, {transit, transit, true}} {
		g := &Gate{cluster: [32]byte{1}, challenge: [32]byte{2}, key: key, authenticated: true, features: c.peer, own: c.own}
		if err := g.Admit(f, Policy{Key: key, Report: true}, false, false); (err == nil) != c.ok {
			t.Fatalf("peer=%v own=%v: %v", c.peer, c.own, err)
		}
	}
}

func TestHelloFeaturesAreOptional(t *testing.T) {
	transit := buildinfo.Features(0).With(buildinfo.FeatureTransit)
	if got := helloFeatures(Frame{Fields: []Field{featuresField(transit)}}); got != transit {
		t.Fatal(got)
	}
	if got := helloFeatures(Frame{}); got != 0 {
		t.Fatal("missing extension is the baseline", got)
	}
	if got := helloFeatures(Frame{Fields: []Field{{Tag: tagFeatures, Value: []byte{1}}}}); got != 0 {
		t.Fatal("malformed extension is the baseline", got)
	}
	// The hello with the extension still parses under the handshake rule.
	raw, err := Encode(Frame{Purpose: Handshake, Kind: 1, Request: 1, Fields: []Field{{Tag: 1, Required: true, Value: make([]byte, 32)}, {Tag: 2, Required: true, Value: make([]byte, 32)}, {Tag: 3, Required: true, Value: make([]byte, 32)}, featuresField(transit)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ReadFrame(bytes.NewReader(raw), 4096); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
