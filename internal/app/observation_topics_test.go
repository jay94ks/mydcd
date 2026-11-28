// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/jay94ks/seafield/internal/observability"
)

func TestObservationTopicUsesAbbreviations(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		report observability.Report
		want   string
	}{
		{observability.Report{Node: "jay2", Host: &observability.Host{}}, "obs/jay2/host"},
		{observability.Report{Node: "jay2", Devices: &observability.Devices{}}, "obs/jay2/dev"},
		{observability.Report{Node: "jay2", Disk: &observability.Disk{Source: "system"}}, "obs/jay2/dsk/sys"},
		{observability.Report{Node: "jay2", Disk: &observability.Disk{Source: "root/r1", RootID: "r1"}}, "obs/jay2/dsk/rt/r1"},
		{observability.Report{Node: "jay2", Usage: &observability.Usage{Tenant: "first"}}, "obs/jay2/use/first"},
		{observability.Report{Node: "jay2", Link: &observability.Link{Peer: "jay3"}}, "obs/jay2/lnk/jay3"},
		{observability.Report{Node: "jay2", Consensus: &observability.Consensus{}}, "obs/jay2/cns"},
		{observability.Report{Node: "jay2", Task: &observability.Task{Key: key}}, "obs/jay2/tsk/" + key},
	} {
		got, ok := observationTopic(tc.report)
		if !ok || got != tc.want {
			t.Errorf("observationTopic(%s) = %q, %v; want %q", tc.report.Source(), got, ok, tc.want)
		}
	}
	if _, ok := observationTopic(observability.Report{Node: "jay2"}); ok {
		t.Error("a report without a source got a topic")
	}
}
