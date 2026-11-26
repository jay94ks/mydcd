// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// CheckAppSubmission is an edge admission rule for a NEW user operation, not
// a new deterministic replay rule. Callers return an existing original receipt
// before this check. Stored executions, historical Raft apply and cleanup keep
// their frozen schema1 artifacts and the same reducer/Inventory machinery.
func (p Policy) CheckAppSubmission(s state.State, op UserOperation) error {
	if op.Change.Action != "begin-app" && op.Change.Action != "standalone-up" && op.Change.Action != "begin-volume-move" {
		return nil
	}
	cmd, err := op.Command()
	if err != nil || op.VerifyOriginal(p.Cluster) != nil {
		return ErrCatalog
	}
	if _, found := s.LookupResult(cmd); found {
		return nil
	}
	a, err := p.Apps(s)
	if err != nil {
		return err
	}
	if op.Change.Action == "begin-volume-move" {
		var q VolumeMoveBegin
		if canonical(op.Change.Payload, &q) != nil {
			return ErrCatalog
		}
		if q.App == nil || q.App.Target == nil {
			return nil // a volume-only explicit operation does not supply an app
		}
		b, err := p.frozenMoveBlueprint(a, op, q)
		if err != nil {
			return err
		}
		return b.CheckAppInput()
	}
	var begin AppBegin
	if canonical(op.Change.Payload, &begin) != nil {
		return ErrCatalog
	}
	for _, upload := range a.uploads {
		if upload.User != op.Change.Principal || upload.Tenant != begin.Tenant || upload.App != begin.App || upload.Deployment != begin.Deployment || upload.ID != begin.Upload {
			continue
		}
		raw, err := upload.Complete()
		if err != nil {
			return err
		}
		b, err := deployment.DecodeBlueprint(raw)
		if err != nil {
			return err
		}
		if op.Change.Action == "standalone-up" {
			return b.CheckStandaloneInput()
		}
		return b.CheckAppInput()
	}
	return ErrCatalog
}
