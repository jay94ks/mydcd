// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// The purpose map in docs/protocol/sfcp/02-purposes.md is this table's
// rendering; the test fails when the two differ (design 4.7). Run with
// SFCP_WRITE_DOCS=1 to rewrite the block after changing the table.
const purposesDoc = "../../docs/protocol/sfcp/02-purposes.md"

var shapeNames = map[Shape]string{
	ShapeHandshake: "handshake", ShapeUnary: "unary", ShapeSensitive: "sensitive",
	ShapeBulk: "bulk", ShapeDuplex: "duplex", ShapeReport: "report", ShapeDatagram: "datagram",
}

func docBytes(n int) string {
	switch {
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%dKiB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func purposeMapMarkdown() string {
	var ids []int
	for p := range purposes {
		ids = append(ids, int(p))
	}
	slices.Sort(ids)
	var b strings.Builder
	b.WriteString("| # | 이름 | 모양 | kind (본문 한도) | 동시 스트림 (peer당) | Unix | 오래 열림 |\n|---|---|---|---|---|---|---|\n")
	for _, id := range ids {
		s := purposes[Purpose(id)]
		var kinds []int
		for k := range s.kinds {
			kinds = append(kinds, int(k))
		}
		slices.Sort(kinds)
		var ks []string
		for _, k := range kinds {
			ks = append(ks, fmt.Sprintf("%d (%s)", k, docBytes(s.kinds[uint8(k)].budget)))
		}
		limit := "–"
		switch {
		case s.unlimited:
			limit = "한도 없음"
		case s.limit > 0 && s.perPeer > 0:
			limit = fmt.Sprintf("%d (%d)", s.limit, s.perPeer)
		case s.limit > 0:
			limit = fmt.Sprint(s.limit)
		}
		mark := func(v bool) string {
			if v {
				return "○"
			}
			return ""
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s | %s |\n", id, s.name, shapeNames[s.shape], strings.Join(ks, ", "), limit, mark(s.local || Purpose(id) == Handshake), mark(s.longLived))
	}
	return b.String()
}

func TestPurposeMapDocMatchesTable(t *testing.T) {
	const begin, end = "<!-- purposes:begin -->\n", "<!-- purposes:end -->"
	raw, err := os.ReadFile(purposesDoc)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	i, j := strings.Index(doc, begin), strings.Index(doc, end)
	if i < 0 || j < i {
		t.Fatal("02-purposes.md has no purposes:begin/end block")
	}
	want := purposeMapMarkdown()
	if doc[i+len(begin):j] == want {
		return
	}
	if os.Getenv("SFCP_WRITE_DOCS") == "1" {
		if err := os.WriteFile(purposesDoc, []byte(doc[:i+len(begin)]+want+doc[j:]), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("docs/protocol/sfcp/02-purposes.md differs from the purpose table; run SFCP_WRITE_DOCS=1 go test -run TestPurposeMapDocMatchesTable ./internal/sfcp/. Want:\n%s", want)
}
