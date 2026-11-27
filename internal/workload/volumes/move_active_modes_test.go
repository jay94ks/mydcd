// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func armedMoveFixture(t *testing.T) (*fixture, Move) {
	t.Helper()
	f := makeFixture(t)
	m := f.prepare("move", f.target)
	f.verified(m, [32]byte{31})
	f.set(f.s.CommitOwner(f.c, "admin", m.Binding.ID, f.s.Revision(), m.Binding.SourceOwnerRevision))
	f.set(f.s.Arm(f.c, "admin", m.Binding.ID, f.s.Revision()))
	m, _ = f.s.Move(m.Binding.ID)
	return f, m
}

func TestMoveActiveReadonlyAndIdleKeepOriginalOwnerAndCleanup(t *testing.T) {
	for _, mode := range []string{"writable", "readonly", "multiple-readers", "idle"} {
		t.Run(mode, func(t *testing.T) {
			f, m := armedMoveFixture(t)
			p := ActiveProof{Binding: m.Binding, Idle: mode == "idle"}
			if !p.Idle {
				p.Consumer = f.acquire("target-reader", 2, mode == "writable")
				p.Running = true
				if mode == "multiple-readers" {
					f.acquire("second-reader", 2, false)
				}
			}
			p.Signature = ed25519.Sign(f.b, ActiveBytes(p))
			f.set(f.s.RecordActive(p))
			revision := f.s.Revision()
			replay, err := f.s.RecordActive(p)
			if err != nil || replay.Revision() != revision {
				t.Fatal("original active fact replay changed state", err)
			}
			f.cleanup(m)
			current, _ := f.s.Move(m.Binding.ID)
			owner, ownerRevision := f.s.Owner()
			if current.Phase != Completed || current.Activated == nil || current.Activated.Idle != p.Idle || current.Activated.Consumer != p.Consumer || owner != m.Binding.Target || ownerRevision != m.CommitRevision || len(f.s.Retained()) != 1 || current.Fence == nil || !current.Irreversible {
				t.Fatal("activation/cleanup lost original move facts or ownership")
			}
			count := 1
			if mode == "idle" {
				count = 0
			} else if mode == "multiple-readers" {
				count = 2
			}
			if len(f.s.Consumers()) != count {
				t.Fatal("completion removed a live target consumer")
			}
		})
	}
}

func TestMoveIdleRejectsLivePinsMixedFactsAndForeignSignatures(t *testing.T) {
	for _, scenario := range []string{"writer", "reader", "running", "consumer", "foreign-signature", "unarmed"} {
		t.Run(scenario, func(t *testing.T) {
			f, m := armedMoveFixture(t)
			p := ActiveProof{Binding: m.Binding, Idle: true}
			signer := f.b
			switch scenario {
			case "writer", "reader":
				f.acquire("live-target", 3, scenario == "writer")
			case "running":
				p.Running = true
			case "consumer":
				p.Consumer = f.acquire("mixed-target", 3, false)
			case "foreign-signature":
				signer = f.a
			case "unarmed":
				// This fixture is deliberately invalid for Active, never native
				// readiness: an owner commit alone cannot consume an Idle fact.
				f.s.d.Moves[0].Phase = OwnerCommitted
				f.s.d.Moves[0].Irreversible = false
			}
			p.Signature = ed25519.Sign(signer, ActiveBytes(p))
			if _, err := f.s.RecordActive(p); err == nil {
				t.Fatal("invalid Idle fact accepted", scenario)
			}
		})
	}
}

func TestMoveActiveLegacySigningBytesAndReadonlyConsumerIdentity(t *testing.T) {
	f, m := armedMoveFixture(t)
	reader := f.acquire("target-reader", 3, false)
	p := ActiveProof{Binding: m.Binding, Consumer: reader, Running: true}
	legacy := struct {
		Binding   Binding
		Consumer  Consumer
		Running   bool
		Signature []byte
	}{Binding: p.Binding, Consumer: p.Consumer, Running: p.Running}
	if !bytes.Equal(ActiveBytes(p), signedBytes("sfc-volume-active-1", legacy)) {
		t.Fatal("absent Idle changed existing schema1 signing bytes")
	}
	for _, change := range []func(*ActiveProof){
		func(p *ActiveProof) { p.Consumer.Writable = true },
		func(p *ActiveProof) { p.Consumer.OwnerRevision++ },
		func(p *ActiveProof) { p.Consumer.Generation++ },
		func(p *ActiveProof) { p.Consumer.Lease.Token++ },
	} {
		bad := p
		change(&bad)
		bad.Signature = ed25519.Sign(f.b, ActiveBytes(bad))
		if _, err := f.s.RecordActive(bad); err == nil {
			t.Fatal("signed fact borrowed another consumer's activation")
		}
	}
	p.Signature = ed25519.Sign(f.b, ActiveBytes(p))
	f.set(f.s.RecordActive(p))
}
