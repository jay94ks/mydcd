// SPDX-License-Identifier: Apache-2.0

package state

import (
	"fmt"
	"strings"
	"testing"
)

// benchState holds n present objects of about 1 KiB, the size of a typical
// managed resource record. See devel/refactor/06-fsm-full-state-write.md.
func benchState(n int) State {
	s := initial()
	value := strings.Repeat("x", 1024)
	for i := 0; i < n; i++ {
		s.objects[fmt.Sprintf("workload/bench/%08d", i)] = Object{Revision: 1, Generation: 1, Value: value, Present: true}
	}
	s.index = 1
	return s
}

// BenchmarkApply is one committed mutation: what fsm.Apply does per Raft log.
// BenchmarkApplyAndEncode adds the full-state encoding fsm.publish writes.
func BenchmarkApply(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		s := benchState(n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c := Command{Actor: "admin", Epoch: 1, RequestID: fmt.Sprint("bench-", i%LedgerLimit), Key: "workload/bench/00000001", Value: "y", Expected: 1}
				if _, _, err := Apply(s, s.Index()+1, c); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkApplyAndEncode(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		s := benchState(n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c := Command{Actor: "admin", Epoch: 1, RequestID: fmt.Sprint("bench-", i%LedgerLimit), Key: "workload/bench/00000001", Value: "y", Expected: 1}
				next, _, err := Apply(s, s.Index()+1, c)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := Encode(next); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
