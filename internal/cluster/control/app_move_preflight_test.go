// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/observability"
)

func TestMoveStoragePreflightUsesExactSignedTargetMeasurement(t *testing.T) {
	f := newBackupCore(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.Deploy)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	public := [32]byte(f.node.Public().(ed25519.PublicKey))
	makeReport := func(change func(*observability.Report)) observability.Report {
		r := observability.Report{Kind: "node-observation", Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Key: public, Index: f.s.Index(), At: 10500,
			Disk: &observability.Disk{Source: "container-runtime", ID: observability.FilesystemID("node-a", "docker"), Mount: "/var/lib/docker-hidden", Device: "/dev/hidden", Filesystem: "ext4", Total: 1000, Used: 500, Free: 500, Available: 400, InodesFree: 100}}
		if change != nil {
			change(&r)
		}
		r.Signature = ed25519.Sign(f.node, observability.SigningBytes(r))
		return r
	}
	base := f.s.Object(CatalogKey)
	for _, tc := range []struct {
		name, want string
		now, need  uint64
		reports    []observability.Report
	}{
		{"same-second fresh", "available", 10999, 400, []observability.Report{makeReport(nil)}},
		{"available not total free", "insufficient", 11000, 450, []observability.Report{makeReport(nil)}},
		{"missing", "unknown", 11000, 300, nil},
		{"stale", "stale", 131000, 300, []observability.Report{makeReport(nil)}},
		{"future time", "unknown", 10000, 300, []observability.Report{makeReport(nil)}},
		{"future index", "unknown", 11000, 300, []observability.Report{makeReport(func(r *observability.Report) { r.Index++ })}},
		{"another node", "unknown", 11000, 300, []observability.Report{makeReport(func(r *observability.Report) { r.Node = "node-b" })}},
		{"another cluster", "unknown", 11000, 300, []observability.Report{makeReport(func(r *observability.Report) { r.Cluster[0]++ })}},
		{"system disk not Docker", "unknown", 11000, 300, []observability.Report{makeReport(func(r *observability.Report) { r.Disk.Source = "system" })}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := f.p.VolumeMoveStoragePreflight(f.s, f.session, tc.now, "tenant", "node-a", tc.need, tc.reports)
			if err != nil || v.State != tc.want || v.Node != "node-a" || v.RequiredBytes != tc.need || !v.valid() || !v.MeasurementOnly {
				t.Fatal("public preflight", v, err)
			}
			if tc.want == "unknown" && (v.AvailableBytes != nil || v.ObservedAt != 0) || tc.want != "unknown" && (v.AvailableBytes == nil || *v.AvailableBytes != 400 || v.ObservedAt != 10500) {
				t.Fatal("measurement absence or original value changed", v)
			}
			raw, _ := json.Marshal(v)
			for _, forbidden := range []string{"docker-hidden", "/dev/hidden", "Signature", "Filesystem", "Cluster"} {
				if bytes.Contains(raw, []byte(forbidden)) {
					t.Fatal("private report field exposed", forbidden)
				}
			}
		})
	}
	tampered := makeReport(nil)
	tampered.Disk.Available++
	v, err := f.p.VolumeMoveStoragePreflight(f.s, f.session, 11000, "tenant", "node-a", 300, []observability.Report{tampered})
	if err != nil || v.State != "unknown" || f.s.Object(CatalogKey) != base {
		t.Fatal("tampered signature or readonly state", v, err)
	}
}

func TestMoveStoragePreflightRequiresCurrentScopedManageVolumesAndDeploy(t *testing.T) {
	f := newBackupCore(t)
	if _, err := f.p.VolumeMoveStoragePreflight(f.s, f.session, 10000, "tenant", "node-a", 300, nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("missing Deploy granted preflight", err)
	}
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.Deploy)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	for _, scope := range [][2]string{{"other", "node-a"}, {"tenant", "node-b"}} {
		if _, err := f.p.VolumeMoveStoragePreflight(f.s, f.session, 10000, scope[0], scope[1], 300, nil); !errors.Is(err, access.ErrDenied) {
			t.Fatal("foreign tenant or node exposed", scope, err)
		}
	}
	if _, err := f.p.VolumeMoveStoragePreflight(f.s, f.session, 1002000, "tenant", "node-a", 300, nil); !errors.Is(err, access.ErrDenied) {
		t.Fatal("expired session granted preflight", err)
	}
	v := MoveStoragePreflight{Node: "node-a", State: "unknown", RequiredBytes: 300, ObservationMaxAge: observability.MaxAge, MeasurementOnly: true}
	if !v.valid() {
		t.Fatal("explicit unknown invalid")
	}
	for _, mutate := range []func(*MoveStoragePreflight){
		func(v *MoveStoragePreflight) { v.MeasurementOnly = false },
		func(v *MoveStoragePreflight) { v.State = "available" },
		func(v *MoveStoragePreflight) { v.ObservedAt = 1 },
		func(v *MoveStoragePreflight) { v.Node = "../node" },
		func(v *MoveStoragePreflight) { v.ObservationMaxAge++ },
	} {
		bad := v
		mutate(&bad)
		if bad.valid() {
			t.Fatal("contradictory or unsafe preflight shape accepted", bad)
		}
	}
}
