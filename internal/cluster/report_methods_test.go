// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"os"
	"strings"
	"testing"
)

// Every node method that writes to Raft is listed, with its class, in the
// table of docs/architecture/raft-and-mydcp.md. Adding one without classifying it fails here.
func TestReportMethodsMatchR14Table(t *testing.T) {
	raw, err := os.ReadFile("../../docs/architecture/raft-and-mydcp.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[ReportClass]string{}
	labels := map[ReportClass]string{ReportCommand: "| 사용자·운영자 명령 |", ReportWork: "| 한 번만 일어나야 하는 작업 기록 |", ReportFact: "| 바뀐 사실 관찰 |", ReportProgress: "| 배포 단계 진행 |"}
	for _, line := range strings.Split(string(raw), "\n") {
		for class, label := range labels {
			if strings.HasPrefix(line, label) {
				// Only the method column; the verdict may mention others.
				rows[class] = strings.Split(line, "|")[2]
			}
		}
	}
	listed := 0
	for class, label := range labels {
		row, ok := rows[class]
		if !ok {
			t.Fatalf("R14 table has no row %q", label)
		}
		listed += strings.Count(row, "`") / 2
	}
	for method, class := range reportMethods {
		if !strings.Contains(rows[class], "`"+method+"`") {
			t.Errorf("%s is class %d in reportMethods but not in that R14 table row", method, class)
		}
	}
	if listed != len(reportMethods) {
		t.Errorf("R14 table lists %d methods, reportMethods has %d", listed, len(reportMethods))
	}
}
