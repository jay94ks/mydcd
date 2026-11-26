// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
)

func TestDeliveryValidationReadsImmutableInventoryAndKeepsExportedOwnership(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	f.receive(f.body)
	f.start("original")
	before, err := json.Marshal(f.d.d)
	if err != nil || f.d.d.Inventory.Active == nil {
		t.Fatal("original active inventory", err)
	}
	owned := f.d.Inventory()
	owned.d.Active.Operation = "external-change"
	for name, service := range owned.d.Active.Plan.Input.Services {
		service.Image = "external-change"
		owned.d.Active.Plan.Input.Services[name] = service
	}
	var wg sync.WaitGroup
	errors := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 2 {
				if err := f.d.validate(); err != nil {
					errors <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error("read-only validation", err)
	}
	after, err := json.Marshal(f.d.d)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("validation/exported copy changed original record", err)
	}
	bad, err := f.d.clone()
	if err != nil {
		t.Fatal(err)
	}
	bad.d.Inventory.Active.Operation = "forged-operation"
	if bad.validate() == nil {
		t.Fatal("active inventory/running selection mismatch accepted")
	}
	bad, err = f.d.clone()
	if err != nil {
		t.Fatal(err)
	}
	bad.d.Inventory.Tenant = "other"
	if bad.validate() == nil {
		t.Fatal("current inventory scope mismatch accepted")
	}
}

func TestDeliveryValidatedBytesKeepIndependentRecordsAndRejectChangedInput(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	f.receive(f.body)
	f.start("original")
	raw, err := f.d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	first, err := DecodeDelivery(raw)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DecodeDelivery(raw)
	if err != nil {
		t.Fatal(err)
	}
	first.d.Inventory.Active.Operation = "changed-local-record"
	for name, service := range first.d.Inventory.Active.Plan.Input.Services {
		service.Image = "changed-local-record"
		first.d.Inventory.Active.Plan.Input.Services[name] = service
	}
	if _, err := first.Encode(); err == nil {
		t.Fatal("changed invalid record inherited an earlier encoding's validity")
	}
	got, err := second.Encode()
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("decoded records share mutable storage", err)
	}
	bad := bytes.Replace(raw, []byte(`"Operation":"original"`), []byte(`"Operation":"forged"`), 1)
	if bytes.Equal(raw, bad) {
		t.Fatal("counterexample did not change original operation")
	}
	if _, err := DecodeDelivery(bad); err == nil {
		t.Fatal("changed execution accepted from validation cache")
	}
	if _, err := DecodeDelivery(append(bytes.Clone(raw), ' ')); err == nil {
		t.Fatal("noncanonical input accepted from cache")
	}
	owned := bytes.Clone(raw)
	if _, err := DecodeDelivery(owned); err != nil {
		t.Fatal(err)
	}
	owned[0] = '!'
	if _, err := DecodeDelivery(owned); err == nil {
		t.Fatal("mutated original byte buffer accepted")
	}
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, e := DecodeDelivery(raw)
			if e != nil {
				failures <- e
				return
			}
			b, e := d.Encode()
			if e != nil || !bytes.Equal(b, raw) {
				failures <- ErrInputs
			}
		}()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		t.Error(e)
	}
}

func TestDeliveryEncodingKeepsExactBytesAndIndependentReturnedBuffers(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	f.receive(f.body)
	f.start("original")
	// Compare to full private validation plus serialization, independent of
	// whether the bounded syntax cache currently contains this record.
	if err := f.d.validate(); err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(f.d.d)
	if err != nil {
		t.Fatal(err)
	}
	first, err := f.d.Encode()
	if err != nil || !bytes.Equal(first, want) {
		t.Fatal("encoding differs from fully validated original record", err)
	}
	first[0] = '!'
	again, err := f.d.Encode()
	if err != nil || !bytes.Equal(again, want) {
		t.Fatal("returned buffer changed record or retained validity bytes", err)
	}
	changed, err := f.d.clone()
	if err != nil {
		t.Fatal(err)
	}
	changed.d.SourceError = "scope"
	actual, err := changed.Encode()
	if err != nil || bytes.Equal(actual, want) {
		t.Fatal("valid local change reused old serialization", err)
	}
	if _, err = DecodeDelivery(actual); err != nil {
		t.Fatal("newly validated bytes cannot be decoded", err)
	}
	unchanged, err := f.d.Encode()
	if err != nil || !bytes.Equal(unchanged, want) {
		t.Fatal("valid change altered independent original record", err)
	}
}
