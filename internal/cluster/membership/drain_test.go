// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"encoding/json"
	"testing"
)

func TestDrainKeepsInstalledMembershipAndOriginalSelection(t *testing.T) {
	d, _, bk := runtimeMembers(t)
	before, _ := d.Entry("b")
	topology, _ := d.Topology()
	n, err := d.BeginDrain("b", "drain-b", 0, json.RawMessage(`{"signed":"original"}`), json.RawMessage(`{"plan":"fixed"}`))
	d = checked(t, n, err)
	after, _ := d.Entry("b")
	current, _ := d.Topology()
	if before.Peer != after.Peer || current.Configuration().Index != topology.Configuration().Index || !d.MemberKey(memberKey(bk)) || !d.WorkKey(memberKey(bk)) || !d.Cordon("b").Enabled || len(d.Drains) != 1 {
		t.Fatal("drain isolated/removed node or lost original plan")
	}
	n, err = d.BeginDrain("b", "drain-b", d.Cordon("b").Revision, json.RawMessage(`{}`), json.RawMessage(`{}`))
	assertRejected(t, d, n, err)
}
