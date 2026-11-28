// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/buildinfo"
)

func TestTable(t *testing.T) {
	if got := table(buildinfo.Features{}, nil); !strings.Contains(got, "기본 기능만") {
		t.Fatal(got)
	}
	f := func(v uint16, p string) buildinfo.Feature {
		return buildinfo.Feature{Group: buildinfo.GroupNetwork, Set: buildinfo.SetNetworkTransit, Version: v, Postfix: p}
	}
	old := buildinfo.MustFeatures(f(1, ""), f(2, ""), f(3, "preview"))
	now := buildinfo.MustFeatures(f(2, ""), f(3, ""), f(4, "preview"))
	got := table(now, &old)
	for _, want := range []string{
		"| network | network-transit | v2–v3 | v4-preview | v1–v2 | v3 추가, 최소 v2로 올림, v4-preview 추가, v3-preview 빠짐 |",
		"| 이전 릴리스 | 변화 |",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
	empty := buildinfo.Features{}
	if got := table(now, &empty); !strings.Contains(got, "| — | 새 기능 집합 |") {
		t.Fatal(got)
	}
	if got := table(empty, &now); !strings.Contains(got, "| — | — | v2–v3 | 빠짐 |") {
		t.Fatal(got)
	}
}

func TestReadNames(t *testing.T) {
	s, err := readNames(strings.NewReader("# 0.1.1\nnetwork-transit-v1\n\nnetwork-transit-v2-preview\n"))
	if err != nil || s.String() != "network-transit-v1,network-transit-v2-preview" {
		t.Fatal(s, err)
	}
	if _, err := readNames(strings.NewReader("network-transit\n")); err == nil {
		t.Fatal("bad name accepted")
	}
}
