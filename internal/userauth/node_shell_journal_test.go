// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func TestManagementJournalRetainsOriginalTypedNodeAndShellRefusals(t *testing.T) {
	for code := state.NodeLastVoter; code <= state.NodeShellUnreachable; code++ {
		t.Run(state.RejectionReason(code), func(t *testing.T) {
			home, client, session, _ := journalFixture(t)
			original := journalOperation(t, client, session, "original-shell")
			original.Change.Action = "open-node-shell"
			original.Change.Payload = json.RawMessage(`{"Node":"node-b","Cols":80,"Rows":24}`)
			original.Signature = ed25519.Sign(client.Self.Private, control.OperationBytes(original))
			if original.VerifyOriginal(client.Cluster) != nil {
				t.Fatal("invalid original shell operation")
			}
			originalBytes := append([]byte(nil), control.OperationBytes(original)...)
			originalSignature := append([]byte(nil), original.Signature...)
			staged, err := StageOperation(home, client, original)
			if err != nil || staged.Result != nil {
				t.Fatal("original shell was not staged as unknown", err)
			}
			current := client
			current.Peers = append(current.Peers[:0:0], current.Peers...)
			current.Peers[0].Endpoint = "127.0.0.1:7444"
			archived := current
			if archived.Profile() != client.Profile() || archived.Verify(session) != nil {
				t.Fatal("a moved endpoint changed the namespace or verification")
			}
			result := state.Result{Code: code, Index: 9, Reason: state.RejectionReason(code)}
			if err := RecordOperationResult(home, archived, session, original, result); err != nil {
				t.Fatal("retained typed refusal could not settle original", err)
			}
			if err := RecordOperationResult(home, archived, session, original, result); err != nil {
				t.Fatal("same original refusal was not idempotent", err)
			}
			loaded, err := LoadOperation(home, archived, session, original.RequestID)
			if err != nil || loaded.Result == nil || *loaded.Result != result || !bytes.Equal(control.OperationBytes(loaded.Operation), originalBytes) || !bytes.Equal(loaded.Operation.Signature, originalSignature) {
				t.Fatal("typed result changed or lost the original signed operation", err)
			}
			again, err := StageOperation(home, client, original)
			if err != nil || again.Result == nil || *again.Result != result || !sameOperation(again.Operation, original) {
				t.Fatal("restaging replaced a settled original", err)
			}
			differentResult := result
			differentResult.Index++
			if !errors.Is(RecordOperationResult(home, client, session, original, differentResult), ErrPrivateState) {
				t.Fatal("different committed receipt replaced original result")
			}
			if !errors.Is(RecordOperationResult(home, client, session, original, state.Result{Code: state.Applied, Index: result.Index}), ErrPrivateState) {
				t.Fatal("typed refusal was rewritten as successful execution")
			}
			differentOperation := original
			differentOperation.RootRevision++
			differentOperation.Signature = ed25519.Sign(client.Self.Private, control.OperationBytes(differentOperation))
			if !errors.Is(RecordOperationResult(home, client, session, differentOperation, result), ErrPrivateState) {
				t.Fatal("receipt rebound to another original CAS")
			}
			if _, err := StageOperation(home, client, differentOperation); !errors.Is(err, ErrPrivateState) {
				t.Fatal("refused original request ID was rebound", err)
			}
			unchanged, err := LoadOperation(home, client, session, original.RequestID)
			if err != nil || unchanged.Result == nil || *unchanged.Result != result || !bytes.Equal(control.OperationBytes(unchanged.Operation), originalBytes) || !bytes.Equal(unchanged.Operation.Signature, originalSignature) {
				t.Fatal("failed replacement changed the original receipt or signed bytes", err)
			}
		})
	}
}

func TestManagementJournalRejectsUnknownMalformedAndTransientResults(t *testing.T) {
	for _, test := range []struct {
		name   string
		result state.Result
	}{
		{"unknown-code", state.Result{Code: 255, Index: 9}},
		{"next-code", state.Result{Code: state.NodeShellUnreachable + 1, Index: 9}},
		{"missing-index", state.Result{Code: state.NodeShellDisabled, Reason: state.RejectionReason(state.NodeShellDisabled)}},
		{"missing-reason", state.Result{Code: state.NodeShellDisabled, Index: 9}},
		{"mismatched-reason", state.Result{Code: state.NodeShellDisabled, Index: 9, Reason: state.RejectionReason(state.NodeShellNotReady)}},
		{"reason-on-generic-result", state.Result{Code: state.Forbidden, Index: 9, Reason: state.RejectionReason(state.NodeShellDisabled)}},
		{"expired", state.Result{Code: state.Expired, Index: 9}},
		{"ledger-full", state.Result{Code: state.LedgerFull, Index: 9}},
	} {
		t.Run(test.name, func(t *testing.T) {
			home, client, session, _ := journalFixture(t)
			original := journalOperation(t, client, session, "original-unknown")
			if _, err := StageOperation(home, client, original); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(RecordOperationResult(home, client, session, original, test.result), ErrPrivateState) {
				t.Fatal("unsettled/malformed result accepted as original outcome")
			}
			unknown, err := LoadOperation(home, client, session, original.RequestID)
			if err != nil || unknown.Result != nil || !sameOperation(unknown.Operation, original) {
				t.Fatal("rejected outcome lost the unknown original", err)
			}
			// Exercise the same validation on private-file read, rather than
			// letting a malformed persisted receipt bypass RecordOperationResult.
			root, err := operationRoot(home, client, session.User, false)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			corrupt := operationRecord(unknown)
			corrupt.Result = &test.result
			if err := writePrivate(root, operationName(original.RequestID), corrupt); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOperation(home, client, session, original.RequestID); !errors.Is(err, ErrPrivateState) || errors.Is(err, ErrOperationMissing) {
				t.Fatal("malformed retained receipt was accepted or mistaken for absence", err)
			}
		})
	}
}
