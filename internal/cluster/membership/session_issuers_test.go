// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
)

func TestSessionIssuersSeparateInstalledVotersFromProviders(t *testing.T) {
	d, b, ak, bk := fixture(t)
	assert := func(d Directory, want ...[32]byte) {
		t.Helper()
		if !slices.Equal(d.SessionIssuers(), want) {
			t.Fatal("unexpected current session issuers", d.SessionIssuers(), want)
		}
	}
	assert(d, memberKey(ak)) // standalone active voter
	d = invite(t, d, b)
	assert(d, memberKey(ak))
	d = dispatch(t, d, "b", ak, 10)
	d = observe(t, d, "b", 12, b)
	d = installed(t, d, "b", bk, 12)
	assert(d, memberKey(ak)) // installed non-voter still cannot issue
	if !d.MemberKey(memberKey(bk)) || !slices.Contains(d.Issuers(), memberKey(bk)) {
		t.Fatal("provider/replication membership was revoked")
	}
	n, err := d.InstallConfiguration(lifecycle.Configuration{Index: 12, Members: []lifecycle.Member{{ID: "a", Key: memberKey(ak), Voter: true}, {ID: "b", Key: memberKey(bk)}}})
	d = checked(t, n, err)
	assert(d, memberKey(ak))
	e, _ := d.Entry("b")
	n, err = d.Promote("b", e.Revision)
	d = checked(t, n, err)
	assert(d, memberKey(ak))
	d = dispatch(t, d, "b", ak, 12)
	b.Voter = true
	d = observe(t, d, "b", 14, b)
	assert(d, memberKey(ak)) // adapter report alone is not installed configuration
	n, err = d.InstallConfiguration(lifecycle.Configuration{Index: 14, Members: []lifecycle.Member{{ID: "a", Key: memberKey(ak), Voter: true}, {ID: "b", Key: memberKey(bk), Voter: true}}})
	d = checked(t, n, err)
	assert(d, memberKey(ak), memberKey(bk))
	d = beginRuntimeNode(t, d, "b", "isolate-b", lifecycle.Isolate)
	assert(d, memberKey(ak))
	if !d.HistoricalMemberKey(memberKey(bk)) || !d.MemberKey(memberKey(bk)) {
		t.Fatal("isolation erased original member identity")
	}
	d = observeRuntimeNode(t, d, "b", bk)
	assert(d, memberKey(ak))
	d = beginRuntimeNode(t, d, "b", "restore-b", lifecycle.Restore)
	assert(d, memberKey(ak))
	d = observeRuntimeNode(t, d, "b", bk)
	assert(d, memberKey(ak), memberKey(bk))
}
