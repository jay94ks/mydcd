// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// BenchmarkCheckpointSmallChange changes one of 1000 records in a book and
// reports the bytes the change writes (R17 B2).
func BenchmarkCheckpointSmallChange(b *testing.B) {
	type record struct{ ID, Body string }
	type book struct {
		Schema   uint8
		Revision uint64
		Rows     []record
	}
	p := Policy{Cluster: [32]byte{1}, TrustRoot: [32]byte{2}}
	d := book{Schema: 1, Revision: 1}
	for i := 0; i < 1000; i++ {
		d.Rows = append(d.Rows, record{fmt.Sprintf("app-%04d", i), strings.Repeat("x", 400)})
	}
	raw, _ := json.Marshal(d)
	s, _ := state.New("admin")
	writes, code := writeCheckpoint(s, AppsKey, p.Cluster, p.TrustRoot, 1, raw)
	c := state.Command{Kind: state.Module, Actor: "admin", Epoch: 1, RequestID: "seed", Key: AppsKey, Value: "seed"}
	s, result, err := state.ApplyReduced(s, 1, c, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, code })
	if err != nil || result.Code != state.Applied {
		b.Fatal(result, err)
	}
	d.Revision, d.Rows[500].Body = 2, strings.Repeat("y", 400)
	raw, _ = json.Marshal(d)
	written := 0
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writes, code = writeCheckpoint(s, AppsKey, p.Cluster, p.TrustRoot, 2, raw)
		if code != state.Applied {
			b.Fatal(code)
		}
		written = 0
		for _, v := range writes {
			written += len(v)
		}
	}
	b.ReportMetric(float64(len(raw)), "book-bytes")
	b.ReportMetric(float64(written), "written-bytes")
}
