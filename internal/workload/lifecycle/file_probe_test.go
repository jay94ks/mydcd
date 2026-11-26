// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

func TestFileContentGuardAndRPCUseSameDigestAndBudget(t *testing.T) {
	r, p := probeRequest(), sourcePolicy()
	query := contract.FileProbe{Service: "web", Path: "/ready", Kind: "regular", ContentDigest: hashText("ready"), MaxBytes: 16}
	call := ProbeCall{Schema: 1, Binding: requestDigest(r), Sequence: 1, DeadlineUnixMilli: r.DeadlineUnixMilli, Kind: "file", File: &query}
	n, err := NormalizeProbeCall(r, p, call)
	if err != nil || n.ID() != call.ID() || *n.File != query {
		t.Fatal("file content normalization lost original binding/input", n, err)
	}
	calls := 0
	native := &probeFixture{file: func(_ context.Context, q contract.FileProbe) (contract.FileResult, error) {
		calls++
		if q != query {
			t.Fatal("native file query changed", q)
		}
		return contract.FileResult{Exists: true, Match: false, Kind: "regular", Mode: 0444}, nil
	}}
	guard, err := GuardProbe(context.Background(), r, p, native)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := guard.File(context.Background(), query); err != nil || !result.Exists || result.Match || calls != 1 {
		t.Fatal("valid negative content result rejected", result, err, calls)
	}
	for _, change := range []func(*contract.FileProbe){
		func(q *contract.FileProbe) { q.ContentDigest = "invalid" },
		func(q *contract.FileProbe) { q.Kind = "directory" },
		func(q *contract.FileProbe) { q.MaxBytes = p.Execution.ProbeBytes + 1 },
		func(q *contract.FileProbe) { q.ContentDigest = "" },
	} {
		bad := query
		change(&bad)
		if _, err := guard.File(context.Background(), bad); err == nil {
			t.Fatal("invalid content request reached native", bad)
		}
		call.File = &bad
		if _, err := NormalizeProbeCall(r, p, call); err == nil {
			t.Fatal("compiled request bypassed file policy", bad)
		}
	}
	if calls != 1 {
		t.Fatal("invalid request issued I/O", calls)
	}
	query.MaxBytes = 0
	q, err := normalizeFile(r, p, query)
	if err != nil || q.MaxBytes != p.Execution.ProbeBytes {
		t.Fatal("content default did not use tenant limit", q, err)
	}
	legacy := contract.FileProbe{Service: "web", Path: "/ready", Kind: "regular"}
	raw, _ := json.Marshal(legacy)
	if bytes.Contains(raw, []byte("ContentDigest")) || bytes.Contains(raw, []byte("MaxBytes")) {
		t.Fatal("metadata-only JSON changed")
	}
}
