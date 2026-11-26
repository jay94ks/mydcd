// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

func TestAppsOwnedCopyPreservesBytesAndSeparatesMutableMetadata(t *testing.T) {
	f, owner, _ := permitDecodeFixture(t)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	a, err := f.p.ReadApps(f.s)
	if err != nil || a.network == nil || len(a.network.Groups) == 0 {
		t.Fatal("checked DNS fixture", err)
	}
	// Include both a filled part and an absent part: copying cannot turn a
	// partial upload into a different candidate or alias its mutable bytes.
	body := bytes.Repeat([]byte("x"), deployment.ArtifactPartBytes+1)
	u, err := deployment.NewUpload("tenant", "first", "copy", "admin", "copy", len(body), sha256.Sum256(body))
	if err == nil {
		u, err = u.Add(0, body[:deployment.ArtifactPartBytes])
	}
	if err != nil {
		t.Fatal(err)
	}
	a.uploads = []deployment.Upload{u}
	wantUploads, _ := json.Marshal(a.uploads)
	wantNetwork, err := a.network.encode()
	if err != nil {
		t.Fatal(err)
	}
	copy, err := a.owned()
	if err != nil {
		t.Fatal(err)
	}
	gotUploads, _ := json.Marshal(copy.uploads)
	gotNetwork, err := copy.network.encode()
	if err != nil || !bytes.Equal(gotUploads, wantUploads) || !bytes.Equal(gotNetwork, wantNetwork) {
		t.Fatal("copy changed canonical metadata", err)
	}
	copy.uploads[0].Parts[0][0] ^= 1
	copy.uploads[0].Parts[1] = []byte("y")
	copy.uploads[0].ID = "changed"
	group := &copy.network.Groups[0]
	group.Network = "changed"
	if len(group.Owners) == 0 || group.Owners[0].Managed == nil {
		t.Fatal("nested mutable DNS fixture")
	}
	group.Owners[0].Managed.Node = "changed"
	group.Owners[0].Config.Zone = "changed.invalid"
	group.Owners[0].Config.Members = append(group.Owners[0].Config.Members, "changed")
	copy.network.Authority, err = copy.network.Authority.ResizeAddresses(4096)
	if err != nil || copy.network.Authority.Revision() == a.network.Authority.Revision() {
		t.Fatal("immutable authority transition fixture", err)
	}
	againUploads, _ := json.Marshal(a.uploads)
	againNetwork, err := a.network.encode()
	if err != nil || !bytes.Equal(againUploads, wantUploads) || !bytes.Equal(againNetwork, wantNetwork) {
		t.Fatal("copy mutated checked input", err)
	}
	_, rows, ok := a.NetworkDNS(owner)
	if !ok || len(rows) == 0 {
		t.Fatal("owned DNS output missing")
	}
	rows[0].Config.Zone = "caller.invalid"
	after, err := a.network.encode()
	if err != nil || !bytes.Equal(after, wantNetwork) {
		t.Fatal("DNS output aliases original groups", err)
	}
	// A finite same-input cost sample, not a throughput/overload test or a
	// timing assertion. Both paths must preserve the same canonical bytes.
	for _, legacy := range []bool{true, false} {
		started := time.Now()
		for range 10 {
			var n *appNetworkState
			if legacy {
				raw, e := a.network.encode()
				if e != nil {
					t.Fatal(e)
				}
				n, err = decodeAppNetwork(raw, f.p.Cluster)
			} else {
				n, err = a.network.owned()
			}
			if err != nil || n.Revision != a.network.Revision {
				t.Fatal(err)
			}
		}
		t.Logf("network copy legacy=%v iterations=10 elapsed=%s", legacy, time.Since(started))
	}
}
