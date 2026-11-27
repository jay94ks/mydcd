// SPDX-License-Identifier: Apache-2.0

package control

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// The Book registry must route every moved action to the same root the old
// CommandKey switch did (R18 S1). These are the old switch's rows.
func TestBookActionsKeepCommandKeys(t *testing.T) {
	want := map[string]string{
		"set-node-shell-policy": NodeShellKey, "set-node-shell-node": NodeShellKey, "set-node-shell-grant": NodeShellKey, "open-node-shell": NodeShellKey, "close-node-shell": NodeShellKey,
		"put-vps-account": VPSKey, "remove-vps-account": VPSKey, "create-vps-node": VPSKey, "delete-vps-node": VPSKey, "stop-vps-node": VPSKey, "start-vps-node": VPSKey, "set-vps-node-cap": VPSKey,
		"prune-node-images": ImageCacheKey,
		"reconnect-tunnel":  TunnelReconnectKey,
		"raft-compact":      CompactKey,
		"cluster-backup":    ClusterBackupKey,
		"set-volume-remote": VolumeSharesKey,
		// Books added after the move (no old switch row).
		"set-cluster-firewall": ClusterFirewallKey,
	}
	for action, key := range want {
		if got := CommandKey(action); got != key {
			t.Errorf("CommandKey(%q) = %q, want %q", action, got, key)
		}
	}
	moved := 0
	for _, b := range books {
		moved += len(b.Actions)
	}
	if moved != len(want) {
		t.Fatalf("books declare %d actions, the old switch had %d for these roots", moved, len(want))
	}
	if CommandKey("no-such-action") != CatalogKey {
		t.Fatal("unknown action must still default to the catalog root")
	}
}

// While books move one at a time, an action must live in exactly one place:
// the registry or the remaining CommandKey switch, never both.
func TestBookActionsLeftTheOldSwitch(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "members.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "CommandKey" {
			return true
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				name, _ := strconv.Unquote(lit.Value)
				if b, dup := actionBook(name); dup {
					t.Errorf("action %q is in book %q and still in the CommandKey switch", name, b.Key)
				}
			}
			return true
		})
		return false
	})
	if len(bookRoots) != len(books) {
		t.Fatalf("indexed %d roots for %d books", len(bookRoots), len(books))
	}
}

func TestIndexBooksRefusesConflicts(t *testing.T) {
	reduce := func(Policy, state.State, state.Command) (map[string][]byte, state.Code) { return nil, state.Invalid }
	defer func() {
		if err := indexBooks(books); err != nil {
			t.Fatal(err)
		}
	}()
	for name, list := range map[string][]Book{
		"duplicate key":    {{Key: "control/a", Reduce: reduce}, {Key: "control/a", Reduce: reduce}},
		"nested key":       {{Key: "control/a", Reduce: reduce}, {Key: "control/a/b", Reduce: reduce}},
		"duplicate action": {{Key: "control/a", Reduce: reduce, Actions: []string{"x"}}, {Key: "control/b", Reduce: reduce, Actions: []string{"x"}}},
		"no reducer":       {{Key: "control/a"}},
		"foreign key":      {{Key: "other/a", Reduce: reduce}},
		"own scope":        {{Key: "control/a", Reduce: reduce, OwnScope: true}},
		"report only":      {{Key: "control/a", Reduce: reduce, ReportOnly: true}},
	} {
		if indexBooks(list) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Every book's keys are known to ledger rotation; a key outside every book
// blocks it. The image-build book was once missing here, so any build
// blocked rotate-ledger for good (R18 F8).
func TestLedgerRotationKnowsEveryBook(t *testing.T) {
	for _, root := range bookRoots {
		if !bookStateKey(root) || !bookStateKey(root+"/records/x") {
			t.Errorf("book %s is unknown to ledger rotation", root)
		}
	}
	if !bookStateKey(ImageBuildKey+"/records/build-one") || !bookStateKey(StorageKey) {
		t.Fatal("image builds or the storage key block ledger rotation")
	}
	if bookStateKey("control/unknown") || bookStateKey(ImageBuildKey+"-x") {
		t.Fatal("a key outside every book is accepted")
	}
}
