// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/desired"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// Real transport handler registration and empty retained native journals;
// no socket Listen, native TUN, Raft fixture or old-key authentication occurs.
func TestHistoricalTunnelJournalsDoNotRegisterOnSharedCurrentTransport(t *testing.T) {
	for _, historicalFirst := range []bool{false, true} {
		name := "current-first"
		if historicalFirst {
			name = "historical-first"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			current, err := identity.Create(filepath.Join(root, "current-key"))
			if err != nil {
				t.Fatal(err)
			}
			old, err := identity.Create(filepath.Join(root, "historical-key"))
			if err != nil {
				t.Fatal(err)
			}
			clusterID := [32]byte{113}
			mesh, err := mydcp.NewTransport(current, clusterID, func(mydcp.Identity) (mydcp.Peer, bool) { return mydcp.Peer{}, false })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := mesh.Close(); err != nil {
					t.Error(err)
				}
			})
			open := func(label string, key *identity.Identity, historical bool) (*Runtime, *tunnelRuntime) {
				t.Helper()
				// Managed admission must remain attached to the retained manager.
				// Empty-journal Open/Close must never create a native consumer.
				manager, err := network.OpenManagerWithAdmission(filepath.Join(root, label+"-bridge.db"), nil, func(context.Context, string, reconcile.Desired) (network.ConsumerBudget, error) {
					t.Error("registration test attempted native consumer admission")
					return network.ConsumerBudget{}, errors.New("unexpected native admission")
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := manager.Close(); err != nil {
						t.Error(err)
					}
				})
				r := &Runtime{Identity: key, controlIdentity: current, historicalOwner: historical, Mesh: mesh, ctx: context.Background(), owner: desired.Owner(clusterID, key.Public), controlPolicy: control.Policy{Cluster: clusterID}, network: manager}
				tunnel, err := openTunnelRuntime(r, filepath.Join(root, label+"-tun.db"))
				if err != nil {
					t.Fatal("owner journal reused current transport handler", label, err)
				}
				t.Cleanup(func() {
					if err := tunnel.Close(); err != nil {
						t.Error(err)
					}
				})
				if tunnel.manager == nil || len(tunnel.manager.Keys()) != 0 || r.commandIdentity().Public != current.Public {
					t.Fatal("retained manager missing or control identity fell back to old key")
				}
				return r, tunnel
			}
			var oldRuntime *Runtime
			var retained *tunnelRuntime
			if historicalFirst {
				oldRuntime, retained = open("historical", old, true)
				open("current", current, false)
			} else {
				open("current", current, false)
				oldRuntime, retained = open("historical", old, true)
			}
			if oldRuntime.Mesh != mesh || mesh.LocalKey() != mydcp.Identity(current.Public) || oldRuntime.Identity.Public == current.Public {
				t.Fatal("native journal owner replaced the current transport identity")
			}
			// Closing only a historical native owner cannot revoke/replace the
			// current daemon's immutable transport registrations or TLS identity.
			if err := retained.Close(); err != nil {
				t.Fatal(err)
			}
			if err := mesh.OnPath(func(context.Context, *mydcp.Session, []byte, int) error { return nil }, nil); !errors.Is(err, mydcp.ErrAdmission) {
				t.Fatal("historical Close removed/replaced current path registration", err)
			}
			if err := mesh.OnPacket(func(*mydcp.Session, mydcp.Frame) error { return nil }); !errors.Is(err, mydcp.ErrAdmission) {
				t.Fatal("historical Close removed/replaced current packet registration", err)
			}
		})
	}
}
