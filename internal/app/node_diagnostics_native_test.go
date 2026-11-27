// SPDX-License-Identifier: Apache-2.0

package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// Extends the existing identity native fixture after its actual CLI download.
// It opens no Docker/kernel fixture and changes neither the original admin nor
// its wallet/defaults. The extra account's changes use ordinary signed APIs.
func verifyManagedNodeDiagnostics(t *testing.T, ctx context.Context, root, node string, admin userauth.Client, peer sfcp.Peer, session access.Session, policy control.Policy, read func() cluster.View, originalArchive string) {
	t.Helper()
	checkNodeDiagnosticArchive(t, originalArchive, node, nil)
	const username = "rq12-diagnostics-reader"
	keyDir := filepath.Join(root, username+"-key")
	key, err := identity.Create(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	home := filepath.Join(root, username+"-home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "cli.yaml")
	intents := filepath.Join(root, username+"-intents")
	if err := os.Mkdir(intents, 0700); err != nil {
		t.Fatal("create private diagnostics management journal home", err)
	}
	putUser := func(callCtx context.Context, id string, expected uint64, account access.User) error {
		account.Revision = 0 // replacement payload and CAS revision are separate
		raw, err := json.Marshal(account)
		if err != nil {
			return err
		}
		op, err := admin.Prepare(callCtx, peer, session, id, control.Change{Schema: 1, Principal: session.User, Action: "put-user", Expected: expected, Payload: raw})
		if err != nil {
			return fmt.Errorf("prepare diagnostic account change: %w", err)
		}
		if _, err = userauth.StageOperation(intents, admin, op); err != nil {
			return fmt.Errorf("stage diagnostic account change: %w", err)
		}
		reply, err := admin.Operation(callCtx, peer, op, false)
		if err != nil {
			return err
		}
		if reply.Result == nil || reply.Result.Code != state.Applied {
			return errors.New("diagnostic fixture account change was not Applied")
		}
		return userauth.RecordOperationResult(intents, admin, session, op, *reply.Result)
	}
	account := access.User{ID: username, Username: username, Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true}}}
	if err = putUser(ctx, "rq12-diagnostics-account-create", 0, account); err != nil {
		t.Fatal("create separate diagnostics account", err)
	}
	defer func() {
		catalog, err := policy.Catalog(read().State)
		if err != nil {
			t.Error("diagnostics account cleanup read", err)
			return
		}
		current, found := catalog.User(username)
		if !found || !current.Enabled {
			return
		}
		current.Enabled = false
		clean, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err = putUser(clean, "rq12-diagnostics-account-disable", current.Revision, current); err != nil {
			t.Error("disable separate diagnostics account", err)
		}
	}()
	cli := func(want int, args ...string) ([]byte, []byte) {
		t.Helper()
		out, why, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), home, profile, args, nil)
		code := 0
		if err != nil {
			var exit interface{ ExitCode() int }
			if !errors.As(err, &exit) {
				t.Fatal("diagnostics CLI did not exit normally", args, err)
			}
			code = exit.ExitCode()
		}
		if code != want {
			t.Fatal("diagnostics CLI", args, code, want, string(why), string(out))
		}
		return out, why
	}
	selected := func(args ...string) []string { return append([]string{"--user", username}, args...) }
	cli(0, "wallet", "init")
	cli(0, selected("login", "--method", "private-key", "--key-file", filepath.Join(keyDir, "key.pem"))...)
	archive := filepath.Join(root, "rq12-current-admin-diagnostics.tar.gz")
	out, _ := cli(0, selected("node", "diagnostics", node, "--output", archive)...)
	var metadata control.NodeDiagnosticsBundle
	if json.Unmarshal(out, &metadata) != nil || len(metadata.Data) != 0 {
		t.Fatal("CLI diagnostic metadata contains bytes or is invalid")
	}
	checkNodeDiagnosticArchive(t, archive, node, &metadata)
	baseline, err := os.ReadFile(archive)
	before, statErr := os.Stat(archive)
	if err != nil || statErr != nil {
		t.Fatal(err, statErr)
	}
	cli(1, selected("node", "diagnostics", node, "--output", archive)...)
	after, err := os.ReadFile(archive)
	afterInfo, statErr := os.Stat(archive)
	if err != nil || statErr != nil || !bytes.Equal(baseline, after) || !os.SameFile(before, afterInfo) || afterInfo.Mode().Perm() != 0600 {
		t.Fatal("O_EXCL refusal changed original diagnostic file", err, statErr)
	}
	sentinel := filepath.Join(root, "rq12-diagnostics-never-overwrite")
	const sentinelBytes = "fixture-private-diagnostic-path-must-not-be-opened"
	if err = os.WriteFile(sentinel, []byte(sentinelBytes), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "rq12-diagnostics-link")
	if err = os.Symlink(sentinel, link); err != nil {
		t.Fatal(err)
	}
	cli(1, selected("node", "diagnostics", node, "--output", link)...)
	linkTarget, linkErr := os.Readlink(link)
	sentinelAfter, err := os.ReadFile(sentinel)
	if err != nil || linkErr != nil || linkTarget != sentinel || string(sentinelAfter) != sentinelBytes {
		t.Fatal("diagnostic output followed/changed a symlink", err, linkErr)
	}
	directory := filepath.Join(root, "rq12-diagnostics-output-dir")
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	cli(1, selected("node", "diagnostics", node, "--output", directory)...)
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("directory output refusal created archive members", err)
	}
	// There is no arbitrary input/log path selector in this command. The
	// attempted selector must fail syntax before creating the output file.
	badOutput := filepath.Join(root, "rq12-diagnostics-unaccepted-path.tar.gz")
	cli(2, selected("node", "diagnostics", node, "--output", badOutput, "--path", sentinel)...)
	if _, err = os.Lstat(badOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsupported path selector created output", err)
	}
	catalog, err := policy.Catalog(read().State)
	current, found := catalog.User(username)
	if err != nil || !found || !current.SystemAdmin {
		t.Fatal("diagnostic admin positive control missing", err)
	}
	current.SystemAdmin = false
	if err = putUser(ctx, "rq12-diagnostics-account-revoke", current.Revision, current); err != nil {
		t.Fatal("revoke only the separate account", err)
	}
	refusedOutput := filepath.Join(root, "rq12-diagnostics-revoked.tar.gz")
	_, why := cli(3, selected("node", "diagnostics", node, "--output", refusedOutput)...)
	if !bytes.Contains(why, []byte("denied")) {
		t.Fatal("revoked cached CLI login did not receive explicit denial", string(why))
	}
	if _, err = os.Lstat(refusedOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("revoked account created an archive", err)
	}
	// A fresh valid login cannot revive the removed system-admin privilege.
	cli(0, selected("login", "--method", "private-key", "--key-file", filepath.Join(keyDir, "key.pem"))...)
	_, why = cli(3, selected("node", "diagnostics", node, "--output", refusedOutput)...)
	if !bytes.Contains(why, []byte("denied")) {
		t.Fatal("current non-admin CLI did not receive explicit denial", string(why))
	}
	if _, err = os.Lstat(refusedOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fresh non-admin account created an archive", err)
	}
	// The original system admin/session was not edited and remains usable for
	// the enclosing fixture's ordinary remove-plan/down and rollback path.
	if _, err = admin.NodeDiagnostics(ctx, peer, session, node); err != nil {
		t.Fatal("separate account refusal affected original admin", err)
	}
}

func checkNodeDiagnosticArchive(t *testing.T, path, node string, metadata *control.NodeDiagnosticsBundle) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > control.NodeDiagnosticsMaxBytes {
		t.Fatal("invalid private bounded diagnostic file", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if metadata != nil {
		copy := *metadata
		copy.Data = raw
		if !copy.Valid(node) {
			t.Fatal("actual CLI archive differs from returned digest/size/limits")
		}
	}
	zip, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	// Bound the expanded tar envelope as well as the JSON bodies. Three
	// fixed members may also carry tar PAX metadata for subsecond timestamps.
	expanded, err := io.ReadAll(io.LimitReader(zip, control.NodeDiagnosticsExpandedBytes+8193))
	closeErr := zip.Close()
	if err != nil || closeErr != nil || len(expanded) > control.NodeDiagnosticsExpandedBytes+8192 {
		t.Fatal("actual archive expanded beyond the bounded tar envelope", err, closeErr)
	}
	allowed := map[string][]string{
		"config-summary.json": {"Schema", "Node", "Endpoint", "Managed", "Network", "Workload", "Ingress"},
		"status.json":         {"Schema", "Index", "MembersRoot", "ConfigurationIndex", "Node", "Phase", "Voter", "Cordoned", "AdmitsWork", "NativeClosed"},
		"sfcd-events.json":    {"At", "Kind", "Scope", "Node", "Tenant", "App", "Service", "Code", "State"},
	}
	seen := map[string]bool{}
	total := int64(0)
	archive := tar.NewReader(bytes.NewReader(expanded))
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header == nil {
			t.Fatal("invalid diagnostic tar header", err)
		}
		keys, accepted := allowed[header.Name]
		if !accepted || seen[header.Name] || header.Mode != 0600 || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > control.NodeDiagnosticsExpandedBytes-total {
			t.Fatal("unexpected diagnostic member/path/size/mode", header, err)
		}
		body, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
		if err != nil || int64(len(body)) != header.Size {
			t.Fatal("truncated diagnostic member", err)
		}
		total += header.Size
		seen[header.Name] = true
		var rows []map[string]json.RawMessage
		if header.Name == "sfcd-events.json" {
			if json.Unmarshal(body, &rows) != nil || len(rows) > 100 {
				t.Fatal("unbounded/invalid diagnostic events")
			}
		} else {
			var row map[string]json.RawMessage
			if json.Unmarshal(body, &row) != nil || string(row["Node"]) != fmt.Sprintf("%q", node) || string(row["Schema"]) != "1" {
				t.Fatal("diagnostic summary lost exact node/schema")
			}
			rows = []map[string]json.RawMessage{row}
		}
		for _, row := range rows {
			for key := range row {
				if !slices.Contains(keys, key) {
					t.Fatal("private/nonallowlisted diagnostic field", header.Name, key)
				}
			}
		}
	}
	if len(seen) != len(allowed) || total > control.NodeDiagnosticsExpandedBytes {
		t.Fatal("missing/unbounded diagnostic archive entries")
	}
}
