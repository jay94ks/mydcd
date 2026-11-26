// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func largeDetailFixture() (Target, Query, Result) {
	target, _, base := logPageFixture()
	query := Query{Schema: 1, Kind: "inspect", Selection: Selection{App: "app", Service: "web"}, MaxBytes: MaxOutput, HistoryLimit: 20}
	detail := &ContainerDetail{Name: "owned-native", ImageID: "sha256:" + strings.Repeat("a", 64)}
	for i := 0; i < 80; i++ {
		detail.Command = append(detail.Command, strings.Repeat("argument-", 450))
	}
	base.Kind = "inspect"
	base.Stdout = nil
	base.Stderr = nil
	base.Detail = detail
	return target, query, base
}

func TestLargeDetailReadPagesAndProductAssemblyPreserveWholeSnapshot(t *testing.T) {
	target, query, original := largeDetailFixture()
	var pages ReadPages
	defer pages.Clear()
	page, err := pages.OpenDetail("alice", target, query, original, [32]byte{9}, 100)
	if err != nil || page.Detail != nil || page.DetailPart == nil {
		t.Fatal("large detail was not fragmented", err)
	}
	assembly, err := NewDetailAssembly(query)
	if err != nil {
		t.Fatal(err)
	}
	defer assembly.Destroy()
	for i := 0; ; i++ {
		if i > 100 || page.Validate(query, target) != nil {
			t.Fatal("invalid or looping frame")
		}
		encoded, _ := json.Marshal(page)
		if len(encoded) > 128<<10 {
			t.Fatal("snapshot fragment expanded native wire frame")
		}
		if err = assembly.Accept(query, page); err != nil {
			t.Fatal(err)
		}
		next, more := assembly.Next()
		if !more {
			break
		}
		query = next
		page, err = pages.Next("alice", target, query, 101)
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := assembly.Result()
	if err != nil {
		t.Fatal(err)
	}
	wantBytes, _ := json.Marshal(original.Detail)
	gotBytes, _ := json.Marshal(got.Detail)
	if !bytes.Equal(wantBytes, gotBytes) || got.DetailPart != nil || got.NextCursor != "" || got.Truncated {
		t.Fatal("partial or changed snapshot returned as complete")
	}
}

func TestDetailAssemblyRejectsChangedHashNativeTimeOrderAndPartialCompletion(t *testing.T) {
	target, query, original := largeDetailFixture()
	var pages ReadPages
	defer pages.Clear()
	first, err := pages.OpenDetail("alice", target, query, original, [32]byte{11}, 100)
	if err != nil {
		t.Fatal(err)
	}
	nextQuery := query
	nextQuery.Cursor = first.NextCursor
	second, err := pages.Next("alice", target, nextQuery, 101)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Result){func(r *Result) { r.Target.NativeID = "other" }, func(r *Result) { r.ObservedAt = r.ObservedAt.Add(1) }, func(r *Result) { r.DetailPart.Digest[0]++ }, func(r *Result) { r.DetailPart.Offset++ }, func(r *Result) { r.DetailPart.Length++ }} {
		assembly, _ := NewDetailAssembly(query)
		if assembly.Accept(query, first) != nil {
			t.Fatal("initial part")
		}
		if _, err = assembly.Result(); err == nil {
			t.Fatal("uncompleted snapshot became success")
		}
		raw, _ := json.Marshal(second)
		var changed Result
		_ = json.Unmarshal(raw, &changed)
		change(&changed)
		if assembly.Accept(nextQuery, changed) == nil {
			t.Fatal("changed snapshot admitted")
		}
		assembly.Destroy()
	}
	if _, err = pages.Next("bob", target, nextQuery, 101); !errors.Is(err, ErrLogCursorExpired) {
		t.Fatal("cross-user detail cursor", err)
	}
	if _, err = pages.Next("alice", target, nextQuery, 100+LogWindowSeconds); !errors.Is(err, ErrLogCursorExpired) {
		t.Fatal("expired detail cursor", err)
	}
}

func TestSmallDetailAssemblyOwnsItsInputAndSharedWindowCapacity(t *testing.T) {
	target, query, original := largeDetailFixture()
	original.Detail.Command = []string{"small"}
	assembly, _ := NewDetailAssembly(query)
	defer assembly.Destroy()
	if err := assembly.Accept(query, original); err != nil {
		t.Fatal(err)
	}
	original.Detail.Command[0] = "caller-changed"
	got, err := assembly.Result()
	if err != nil || got.Detail.Command[0] != "small" {
		t.Fatal("caller mutated accepted complete snapshot", err)
	}
	var pages ReadPages
	defer pages.Clear()
	if _, err = pages.OpenDetail("", target, query, original, [32]byte{1}, 100); err == nil {
		t.Fatal("small detail bypassed user binding")
	}
	if _, err = pages.OpenDetail("alice", target, query, original, [32]byte{}, 100); err == nil {
		t.Fatal("zero window nonce admitted")
	}
}

func TestDetailAssemblyRejectsCorruptedBytesAtWholeSnapshotBoundary(t *testing.T) {
	target, query, original := largeDetailFixture()
	var pages ReadPages
	defer pages.Clear()
	page, err := pages.OpenDetail("alice", target, query, original, [32]byte{12}, 100)
	if err != nil {
		t.Fatal(err)
	}
	page.DetailPart.Data[0] ^= 1 // same signed metadata, invalid content digest
	assembly, _ := NewDetailAssembly(query)
	defer assembly.Destroy()
	for {
		if err = assembly.Accept(query, page); err != nil {
			t.Fatal("fragment grammar unexpectedly rejected intact metadata", err)
		}
		next, more := assembly.Next()
		if !more {
			break
		}
		query = next
		page, err = pages.Next("alice", target, query, 101)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = assembly.Result(); err == nil {
		t.Fatal("corrupted complete JSON was returned without whole-snapshot hash check")
	}
}
