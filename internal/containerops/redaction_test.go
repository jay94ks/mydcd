// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestSecretRedactionPreservesChunkIndependentOverlappingUnion(t *testing.T) {
	values := []RedactionValue{{Reference: "tenant/credentials/TOKEN", Value: []byte("abcd")}, {Reference: "tenant/credentials/KEY", Value: []byte("cdef")}}
	raw := []byte("begin abcdef middle abcd end")
	want := "begin «가림: tenant/credentials/TOKEN» middle «가림: tenant/credentials/TOKEN» end"
	for width := 1; width <= len(raw); width++ {
		var output bytes.Buffer
		r, err := NewRedactor(&output, values)
		if err != nil {
			t.Fatal(err)
		}
		for at := 0; at < len(raw); at += width {
			if _, err = r.Write(raw[at:min(at+width, len(raw))]); err != nil {
				t.Fatal(err)
			}
		}
		if err = r.Finish(); err != nil {
			t.Fatal(err)
		}
		r.Destroy()
		if output.String() != want {
			t.Fatalf("width %d output %q", width, output.String())
		}
	}
	if string(values[0].Value) != "abcd" {
		t.Fatal("filter destroyed caller-owned value")
	}
}

func TestSecretRedactionRetainsPrefixesAndDestroysWithoutFlush(t *testing.T) {
	var output bytes.Buffer
	value := RedactionValue{Reference: "tenant/group/PASSWORD", Value: []byte("private-value-392")}
	r, err := NewRedactor(&output, []RedactionValue{value})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = r.Write([]byte("safe private-val"))
	if output.String() != "safe " {
		t.Fatal("incomplete Secret prefix escaped", output.String())
	}
	if raw, err := json.Marshal(r); err == nil || len(raw) != 0 {
		t.Fatal("private matcher was encoded")
	}
	if raw := fmt.Sprintf("%+v", r); strings.Contains(raw, "private-value") {
		t.Fatal("matcher logged private bytes")
	}
	r.Destroy()
	if output.String() != "safe " {
		t.Fatal("cancel flushed private prefix")
	}
	if _, err = r.Write([]byte("ue-392")); !errors.Is(err, ErrRedaction) {
		t.Fatal("closed filter reused")
	}
	r, err = NewRedactor(&output, []RedactionValue{value})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	_, _ = r.Write([]byte("private-val"))
	if err = r.Finish(); err != nil || strings.Contains(output.String(), "private-val") {
		t.Fatal("EOF leaked recognizable prefix", err)
	}
}

type redactionShortWriter struct{}

func TestBorrowedRedactionStreamsKeepIndependentStateUntilOwnerJoin(t *testing.T) {
	var output bytes.Buffer
	parent, err := NewRedactor(&output, []RedactionValue{{Reference: "key", Value: []byte("token-value")}})
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Destroy()
	a, err := parent.BorrowStream()
	if err != nil {
		t.Fatal(err)
	}
	b, err := parent.BorrowStream()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.Write([]byte("token-"))
	_, _ = b.Write([]byte("other\n"))
	_, _ = a.Write([]byte("value\n"))
	if err := a.Finish(); err != nil {
		t.Fatal(err)
	}
	a.Destroy()
	_, _ = b.Write([]byte("token-value"))
	if err := b.Finish(); err != nil {
		t.Fatal(err)
	}
	b.Destroy()
	// Borrowed child destruction must not erase the parent's compiled bytes.
	got, err := parent.RedactString("token-value")
	if err != nil || strings.Contains(got, "token-value") || strings.Count(output.String(), "«가림: key»") != 2 {
		t.Fatal("borrowed stream altered another matcher", err)
	}
}

func TestRedactionForkKeepsIndependentPrefixesAfterParentDestroy(t *testing.T) {
	var output bytes.Buffer
	parent, err := NewRedactor(&output, []RedactionValue{{Reference: "key", Value: []byte("token-value")}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := parent.Fork()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Destroy()
	b, err := parent.Fork()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy()
	parent.Destroy()
	if _, err := parent.Fork(); !errors.Is(err, ErrRedaction) {
		t.Fatal("closed parent forked", err)
	}
	_, _ = a.Write([]byte("token-"))
	_, _ = b.Write([]byte("other\n"))
	_, _ = a.Write([]byte("value\n"))
	if err := a.Finish(); err != nil {
		t.Fatal(err)
	}
	a.Destroy()
	_, _ = b.Write([]byte("token-value"))
	if err := b.Finish(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); strings.Contains(got, "token-") || strings.Contains(got, "value") || strings.Count(got, "«가림: key»") != 2 {
		t.Fatal(got)
	}
}

func (redactionShortWriter) Write(p []byte) (int, error) { return max(0, len(p)-1), nil }

func TestSecretRedactionBudgetsBinaryRepetitionAndOutputFailure(t *testing.T) {
	var output bytes.Buffer
	if _, err := NewRedactor(&output, []RedactionValue{{Value: make([]byte, MaxRedactionBytes+1)}}); !errors.Is(err, ErrRedaction) {
		t.Fatal("unbounded filter")
	}
	values := []RedactionValue{{Reference: "binary", Value: []byte{0, 1, 2}}, {Reference: "repeat", Value: []byte(strings.Repeat("x", 4096))}}
	r, err := NewRedactor(&output, values)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	for _, part := range [][]byte{{0, 1}, {2, ' '}, []byte(strings.Repeat("x", 8192))} {
		if _, err = r.Write(part); err != nil {
			t.Fatal(err)
		}
	}
	if err = r.Finish(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "«가림: binary» «가림: repeat»" {
		t.Fatal("overlapping binary/repeated value", got)
	}
	r, err = NewRedactor(redactionShortWriter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	if _, err = r.Write([]byte("visible")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("output failure ignored", err)
	}
}

func TestDisplayFieldRedactionReusesPatternsWithoutSharingPrefixState(t *testing.T) {
	r, err := NewRedactor(io.Discard, []RedactionValue{{Reference: "tenant/signing/KEY", Value: []byte("private-marker-719")}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	for _, value := range []string{"one private-marker-719 two", "private-marker-719", "safe text"} {
		got, err := r.RedactString(value)
		if err != nil || strings.Contains(got, "private-marker-719") || value == "safe text" && got != value {
			t.Fatal("display filter destroyed parent's patterns/state", err)
		}
	}
}
