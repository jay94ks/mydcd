// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// This is the actual signing tail called by Client.Prepare after its existing
// whoami query. Reuse the private journal/session fixture; no RPC server or
// alternate preparation algorithm is introduced for this test.
func TestPrepareOperationStandaloneCASModeAndOriginalJournal(t *testing.T) {
	for _, action := range []string{"standalone-pin", "standalone-remove", "standalone-up", "standalone-stop", "standalone-start", "standalone-restart", "restart-task"} {
		t.Run(action, func(t *testing.T) {
			home, c, session, _ := journalFixture(t)
			target := [32]byte{7}
			var payload any = control.StandaloneChange{Tenant: "tenant", Name: "debug", Operation: "once", Target: &target}
			switch action {
			case "standalone-up":
				payload = control.AppBegin{Standalone: &control.StandaloneDefinition{Name: "debug", Lifetime: "fixed", Mode: "entrypoint"}, Target: &target, Tenant: "tenant", App: "scope", Deployment: "deploy", Upload: "upload", Operation: "once"}
			case "standalone-stop", "standalone-start", "standalone-restart":
				payload = control.TaskRestartChange{Standalone: "debug", Tenant: "tenant", Operation: "once", Target: target, ManagementTarget: &target}
			case "restart-task":
				q := control.TaskRestartChange{Tenant: "tenant", App: "app", Operation: "once", Target: target}
				q.Selection.Service = "web"
				payload = q
			}
			raw, err := control.ChangeBytes(action, session.User, 3, payload)
			if err != nil {
				t.Fatal(err)
			}
			var change control.Change
			_ = json.Unmarshal(raw, &change)
			op, err := c.prepareOperation(session, "once", change, 3, 17, session.IssuedAt)
			command, commandErr := op.Command()
			if err != nil || commandErr != nil || control.StandaloneCASAllowed(op.Change) != (action != "restart-task") || op.RootRevision != 17 || op.Epoch != 3 || command.Kind != state.ModuleAppCAS || op.VerifyOriginal(c.Cluster) != nil {
				t.Fatal("Prepare signing mode/root/epoch/signature", err, commandErr)
			}
			if _, err = StageOperation(home, c, op); err != nil {
				t.Fatal(err)
			}
			result := state.Result{Code: state.ConditionFailed, Index: 20, Revision: 19, Generation: 1}
			if err = RecordOperationResult(home, c, session, op, result); err != nil {
				t.Fatal(err)
			}
			stored, err := LoadOperation(home, c, session, op.RequestID)
			if err != nil || stored.Result == nil || *stored.Result != result || !bytes.Equal(control.OperationBytes(stored.Operation), control.OperationBytes(op)) || !bytes.Equal(stored.Operation.Signature, op.Signature) {
				t.Fatal("journal changed original signed mode/CAS/receipt", err)
			}
		})
	}
}
