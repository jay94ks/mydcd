// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
)

func TestAuthorityValidatedBytesKeepOwnedRecordsAndCurrentPolicy(t *testing.T) {
	r := routeBoth(t)
	raw := encode(t, r.f.a)
	validatedAuthority.Store(nil)
	first, err := DecodeAuthority(raw)
	if err != nil {
		t.Fatal(err)
	}
	checked := validatedAuthority.Load()
	if checked == nil {
		t.Fatal("exact valid snapshot not retained")
	}
	second, err := DecodeAuthority(raw)
	if err != nil || validatedAuthority.Load() != checked {
		t.Fatal("unchanged snapshot validation", err)
	}
	// Mutate the owned decoder result directly to exercise every layer that
	// public consumers cannot reach. Neither another result nor the cache may
	// share these maps/slices/route pointers.
	for id, c := range first.references.Consumers {
		c.Route.Policy.Ports[0].First++
		c.Members[0].Since++
		first.references.Consumers[id] = c
		break
	}
	for id := range first.references.Floors {
		delete(first.references.Floors, id)
	}
	got, err := second.Encode()
	if err != nil || !bytes.Equal(raw, got) {
		t.Fatal("decoded Authority aliases another result", err)
	}
	r.f.a = second
	proof, err := r.b.AppliedProof(r.f.c, r.f.n, r.f.a)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, proof, r.b.boot, r.tuple, routeClock(r.a, 150)); err != nil {
		t.Fatal("current positive route", err)
	}
	r = routeWithdraw(t, r)
	if _, _, err := r.a.BorrowFlow(r.f.c, r.f.n, second, proof, r.b.boot, r.tuple, routeClock(r.a, 151)); err == nil {
		t.Fatal("validated bytes retained a withdrawn route grant")
	}
	owned := bytes.Clone(raw)
	if _, err := DecodeAuthority(owned); err != nil {
		t.Fatal(err)
	}
	owned[0] = '!'
	if _, err := DecodeAuthority(owned); err == nil {
		t.Fatal("caller-mutated bytes accepted")
	}
	if _, err := DecodeAuthority(append(bytes.Clone(raw), ' ')); err == nil {
		t.Fatal("noncanonical bytes accepted")
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := DecodeAuthority(raw)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := a.Encode()
			if err != nil || !bytes.Equal(raw, got) {
				t.Error("concurrent decoder changed snapshot", err)
			}
		}()
	}
	wg.Wait()
}

func TestAuthorityValidatedBytesRejectChangedSignatureAndOversizeRetention(t *testing.T) {
	f, _ := networkChangeFixture(t, false)
	f = changeCommit(t, sourceFence(t, changeDrain(t, f)))
	raw := encode(t, f.a)
	if _, err := DecodeAuthority(raw); err != nil {
		t.Fatal(err)
	}
	var disk authoritySnapshot
	if err := json.Unmarshal(raw, &disk); err != nil || len(disk.Archives) == 0 {
		t.Fatal("signed archive fixture", err)
	}
	disk.Archives[0].Closed.Signature[0] ^= 1
	bad, err := json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAuthority(bad); err == nil {
		t.Fatal("same revision with changed signature accepted")
	}
	// Large input must take full validation and cannot displace the bounded
	// entry. Spaces here deliberately make that input noncanonical.
	checked := validatedAuthority.Load()
	large := append(bytes.Clone(raw), bytes.Repeat([]byte{' '}, authorityValidationBytes)...)
	if _, err := DecodeAuthority(large); err == nil || validatedAuthority.Load() != checked {
		t.Fatal("oversize invalid input retained or accepted", err)
	}
}
