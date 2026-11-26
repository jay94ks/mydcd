// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestSignedPathSampleBindings(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	from := Identity(key.Public().(ed25519.PublicKey))
	to, cluster := Identity{2}, [32]byte{3}
	scope := []byte("exact committed tunnel anchors")
	p := PathSample{Schema: 1, Cluster: cluster, From: from, To: to, Scope: scope, MTU: 1280, At: time.Now().UnixMilli(), Budget: PacketBudget{Connection: [32]byte{4}, Generation: 1, UDPBytes: 1441, FrameBytes: 1404, IPBytes: 1284, ObservedAt: time.Now().Add(-time.Second)}}
	p.Signature = ed25519.Sign(key, pathBytes(p))
	if !validSample(p, cluster, from, to, scope, 1280, [32]byte{}) {
		t.Fatal("valid signature denied")
	}
	for _, change := range []func(*PathSample){func(p *PathSample) { p.Cluster[0]++ }, func(p *PathSample) { p.To[0]++ }, func(p *PathSample) { p.Scope = []byte("other") }, func(p *PathSample) { p.Budget.Generation++ }, func(p *PathSample) { p.Budget.Connection[0]++ }, func(p *PathSample) { p.MTU++ }, func(p *PathSample) { p.Request[0]++ }, func(p *PathSample) { p.At -= 31_000 }} {
		bad := p
		change(&bad)
		if validSample(bad, cluster, from, to, scope, 1280, [32]byte{}) {
			t.Fatal("modified signed scope/budget admitted")
		}
	}
	if (PathPair{}).MTU() != 0 {
		t.Fatal("empty path is Ready")
	}
}
