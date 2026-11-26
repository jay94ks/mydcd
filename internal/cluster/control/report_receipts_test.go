// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func TestVolumeNodeReportContentIdentityAndReplay(t *testing.T) {
	for _, kind := range []string{"backup", "restore"} {
		t.Run(kind, func(t *testing.T) {
			f, q := restoreCore(t)
			var raw []byte
			var cmd state.Command
			var err error
			owner := [32]byte(f.node.Public().(ed25519.PublicKey))
			if kind == "restore" {
				restoreLimits(f, q.MaxBytes, 1)
				f.apply("begin-restore", "begin-volume-restore", 2, q, state.Applied)
				raw, _ = json.Marshal(restoreReport(t, f, q, "restored"))
				cmd, err = f.p.ResolveVolumeRestoreReport(f.s, owner, raw)
			} else {
				j, _ := f.view().Backup(f.scope, "one")
				f.apply("delete-backup", "delete-volume-backup", j.Revision, VolumeBackupSelection{f.scope, "one"}, state.Applied)
				raw, _ = json.Marshal(f.report("one", "gone"))
				cmd, err = f.p.ResolveVolumeBackupReport(f.s, owner, raw)
			}
			if err != nil || cmd.Kind != state.ModuleReport || cmd.RequestID != state.ReportRequestID(cmd) || !f.p.AdmitModule(f.s, cmd) {
				t.Fatal("signed content-bound report not admitted", err)
			}
			for _, mutate := range []func(*state.Command){
				func(c *state.Command) { c.Expected++ },
				func(c *state.Command) { c.Actor = "node/foreign" },
				func(c *state.Command) { c.RequestID = "checkpoint/forged" },
			} {
				bad := cmd
				mutate(&bad)
				if f.p.AdmitModule(f.s, bad) {
					t.Fatal("changed report admitted")
				}
			}
			// Node reports are ModuleReport only; a Module-kind copy is not admitted.
			module := cmd
			module.Kind = state.Module
			if _, result, applyErr := state.ApplyAdmitted(f.s, f.s.Index()+1, module, f.p.Validate, f.p.Reduce, f.p.AdmitModule); applyErr == nil && result.Code == state.Applied {
				t.Fatal("Module-kind node report applied")
			}
			for _, candidate := range []state.Command{cmd} {
				next, result, applyErr := state.ApplyAdmitted(f.s, f.s.Index()+1, candidate, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
				if applyErr != nil || result.Code != state.Applied {
					t.Fatal("report failed typed reducer", result, applyErr)
				}
				_, replay, applyErr := state.ApplyAdmitted(next, next.Index()+1, candidate, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
				if applyErr != nil || replay != result {
					t.Fatal("original report result changed", replay, applyErr)
				}
				var resolved state.Command
				if kind == "restore" {
					resolved, err = f.p.ResolveVolumeRestoreReport(next, owner, raw)
				} else {
					resolved, err = f.p.ResolveVolumeBackupReport(next, owner, raw)
				}
				if err != nil || resolved != candidate {
					t.Fatal("retry replaced original signed report identity", err)
				}
			}
		})
	}
}
