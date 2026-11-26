// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func TestRealBoundaryManagedAppComposeCLIObservations(t *testing.T) {
	testRealManagedAppOwner(t, true, true, true, true, true)
}

func TestRealBoundaryManagedAppComposeGroupCLI(t *testing.T) {
	testRealManagedAppOwner(t, true, true, true, true, true, true)
}

func TestP0RealBoundaryManagedNetworkComposeCLI(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppManagedNetwork, true, false, true)
}

// The CLI is prebuilt as the ordinary user. The owned native fixture executes
// only that binary; it never builds as root or supplies owner observations.
func prepareManagedComposeCLI(t *testing.T, ctx context.Context, root string, user userauth.Client, peer mydcp.Peer, document, managementInput []byte, p control.Policy, read func() cluster.View, refresh bool, waitBudget time.Duration, groups ...string) []func() {
	t.Helper()
	binary := os.Getenv("MYDC_TEST_CLI")
	if !filepath.IsAbs(binary) {
		t.Fatal("explicit user-prebuilt CLI required")
	}
	home := filepath.Join(root, "cli-home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	profile, file := filepath.Join(root, "cli.yaml"), filepath.Join(root, "compose.yaml")
	config := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n", user.Cluster, peer.Key, peer.Endpoint)
	if err := os.WriteFile(profile, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, document, 0600); err != nil {
		t.Fatal(err)
	}
	var passwordFDs []*os.File
	call := func(want int, args ...string) []byte {
		t.Helper()
		output, diagnostic, err := runManagedCLICommand(ctx, binary, home, profile, args, passwordFDs)
		code := 0
		if err != nil {
			if exited, ok := err.(*exec.ExitError); ok {
				code = exited.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if code != want {
			t.Fatal("CLI", args, "exit", code, "want", want, string(diagnostic), string(output))
		}
		return output
	}
	var serverVersion userauth.ServerVersion
	if raw := call(0, "server-version"); json.Unmarshal(raw, &serverVersion) != nil || serverVersion.Version == "" || serverVersion.Protocol != 1 {
		t.Fatal("real Runtime version before wallet/login", string(raw))
	}
	call(0, "wallet", "init")
	call(0, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	prepareManagedCheckerCLI(t, root, document, call)
	if len(managementInput) != 0 {
		applyManagementChanges(t, root, "prepare-network", managementInput, func(args ...string) { call(0, args...) })
		waitManagementNetworks(t, ctx, managementInput, p, read)
	}
	args := []string{"compose", "up", "--operation", "rollout", "--tenant", "tenant", "-f", file, "--no-input"}
	for i, group := range groups {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		password := []byte("private-native-group-password\n")
		_, err = writer.Write(password)
		clear(password)
		_ = writer.Close()
		if err != nil {
			t.Fatal(err)
		}
		passwordFDs = append(passwordFDs, reader)
		args = append(args, "--group-password-fd", fmt.Sprintf("%s=%d", group, 3+i))
	}
	call(0, args...)
	for _, reader := range passwordFDs {
		_ = reader.Close()
	}
	passwordFDs = nil
	t.Logf("prebuilt CLI resolves required Groups from original signed begin, authenticates exact scope over SecretInput using %d explicit FDs, then accepts same app; no fixture approval supplied for this CLI requester", len(groups))
	waited := func(condition, operation string) {
		t.Helper()
		args := []string{"compose", "wait", "-p", "app", "--tenant", "tenant", "--operation", operation, "--condition", condition}
		if waitBudget > 0 {
			// Observe the one original operation within this fixture's explicit
			// development budget; do not resubmit it or change product defaults.
			args = append([]string{"--timeout", waitBudget.String()}, args...)
		}
		raw := call(0, args...)
		var reply struct {
			Complete bool
			Observed control.AppView
		}
		if json.Unmarshal(raw, &reply) != nil || !reply.Complete || condition == "healthy" && reply.Observed.Health != "Healthy" || condition == "retired" && (reply.Observed.Retirement == nil || reply.Observed.Retirement.Status != "Retired") {
			t.Fatal("wait result", string(raw))
		}
	}
	healthy := func() {
		waited("healthy", "rollout")
		diffArgs := []string{"compose", "diff", "--tenant", "tenant", "-f", file}
		if input, err := deployment.ParseApp(document); err == nil {
			program, _, err := input.LifecycleProgram()
			if err != nil {
				t.Fatal(err)
			}
			for _, script := range program.Scripts {
				if script.Ref == nil {
					diffArgs = []string{"compose", "diff", "--tenant", "tenant", "--source-operation", "rollout"}
					break
				}
			}
		}
		raw := bytes.TrimSpace(call(0, diffArgs...))
		diff, err := control.DecodeAppDiff(raw)
		if err != nil || diff.InventoryRevision == 0 {
			t.Fatal("actual inventory diff", err)
		}
		for _, change := range diff.Changes {
			if change.Action != "Keep" {
				t.Fatal("same app diff", change)
			}
		}
		if len(groups) > 1 {
			// All password descriptors are closed. Existing signed approvals must
			// suffice; a second provider verifier read is detected by Vault audit.
			call(0, "compose", "resume", "--operation", "rollout", "--tenant", "tenant", "--no-input")
			call(0, "compose", "up", "--operation", "rollout", "--tenant", "tenant", "--no-input")
		}
		if refresh {
			apps, err := p.Apps(read().State)
			if err != nil {
				t.Fatal(err)
			}
			e, _ := apps.Execution("tenant", "app")
			kind := "bridge"
			if len(managementInput) != 0 {
				kind = "network-ref"
			}
			bridge := deployment.ResourceKey(kind, "tenant", "app", "app/node-a")
			original, found := e.Stage(bridge)
			if !found || original.Observation == nil {
				t.Fatal("missing original network observation", kind)
			}
			// Completed success must not freeze the original network observation.
			for {
				apps, err = p.Apps(read().State)
				if err != nil {
					t.Fatal(err)
				}
				e, _ = apps.Execution("tenant", "app")
				current, found := e.Stage(bridge)
				if !found || current.Observation == nil {
					t.Fatal("missing current network observation", kind)
				}
				if current.Observation.Sequence > original.Observation.Sequence {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("completed bridge did not refresh", ctx.Err())
				case <-time.After(100 * time.Millisecond):
				}
			}
			waited("healthy", "rollout")
		}

		shared := read().State
		apps, _ := p.Apps(shared)
		catalog, _ := p.Catalog(shared)
		e, _ := apps.Execution("tenant", "app")
		var newest uint64
		for _, step := range e.Steps() {
			stage, _ := e.Stage(step.Key)
			if stage.Observation != nil {
				newest = max(newest, stage.Observation.At)
			}
		}
		rows, _, err := apps.ObservedPage(catalog, "admin", "tenant", "", newest+control.AppObservationMaxAge+1)
		if err != nil || len(rows) != 1 || rows[0].Operation.Status != "Succeeded" || rows[0].Health != "Unknown" {
			t.Fatal("historical success became fresh health", rows, err)
		}
		t.Log("prebuilt CLI up -> actual Vault/Secret/Volume/Task -> fresh Healthy wait and Keep diff; completed Bridge refreshes original signed observation; expired owner evidence remains Unknown despite Succeeded")
	}
	down := func() { call(0, "compose", "down", "-p", "app", "--tenant", "tenant", "--operation", "stop-app") }
	retired := func() {
		waited("retired", "stop-app")
		call(4, "compose", "wait", "-p", "app", "--tenant", "tenant", "--operation", "rollout")
		t.Log("prebuilt CLI down -> automatic actual owner closure/whole reference return/retained Volume -> original retired wait; retired deployment cannot satisfy Healthy")
	}
	return []func(){healthy, down, retired}
}

// Protected fixture inputs share the same descriptor layout for single-node
// and two-node real CLI cases. The supplied Secret FDs retain their numbers.
func runManagedCLICommand(ctx context.Context, binary, home, profile string, args []string, inputs []*os.File) ([]byte, []byte, error) {
	return runManagedCLICommandInput(ctx, binary, home, profile, args, inputs, nil)
}

func runManagedCLICommandInput(ctx context.Context, binary, home, profile string, args []string, inputs []*os.File, stdin io.Reader) ([]byte, []byte, error) {
	if tenant, ok := tenantUseArgs(args); ok {
		return useNativeTenant(ctx, binary, home, tenant)
	}
	if newFrameCommand(args) {
		return runNewFrameCLI(ctx, binary, home, args, inputs, stdin)
	}
	// A test's own 'wallet init' finds the wallet already made by the login below.
	if len(args) == 2 && args[0] == "wallet" && args[1] == "init" {
		if _, e := os.Stat(filepath.Join(home, ".mydc", "wallet.bin")); e == nil {
			return nil, nil, nil
		}
	}
	if legacyLoginArgs(args) {
		// The new commands keep their key in the wallet, so the old login
		// needs one too. Fixtures that never ran 'wallet init' get it here.
		if _, e := os.Stat(filepath.Join(home, ".mydc", "wallet.bin")); errors.Is(e, fs.ErrNotExist) {
			if out, diagnostic, e := runLegacyCLICommandInput(ctx, binary, home, profile, []string{"wallet", "init"}, nil, nil); e != nil {
				return out, append(diagnostic, []byte("native wallet init: "+e.Error()+"\n")...), e
			}
		}
	}
	out, diagnostic, err := runLegacyCLICommandInput(ctx, binary, home, profile, args, inputs, stdin)
	if err == nil && legacyLoginArgs(args) {
		// The old login only fills the --config profile. Commands moved to
		// the new frame read a context instead: give them the same user.
		if e := ensureNativeContext(ctx, binary, home, profile, args); e != nil {
			return out, append(diagnostic, []byte("native context: "+e.Error()+"\n")...), e
		}
	}
	return out, diagnostic, err
}

// Commands the new frame (cmd/mydc commands.go newRoot) owns. They take a
// context, not --config, so the fixture runs them against the context that
// ensureNativeContext made after the old login. login itself stays old here.
var nativeNewFrame = map[string]bool{"context": true, "key": true, "app": true, "op": true, "volume": true, "registry": true, "image": true, "build": true, "cd": true, "certificate": true, "ingress": true, "lifecycle": true, "node": true, "cluster": true, "events": true, "secret": true}

// nativeCommandWord skips leading global options (--tenant X, --timeout D).
func nativeCommandWord(args []string) (int, string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--tenant", "--timeout", "--user", "--context", "--peer":
			i++
			continue
		case "--no-input", "-y":
			continue
		}
		return i, args[i]
	}
	return len(args), ""
}

func newFrameCommand(args []string) bool {
	_, word := nativeCommandWord(args)
	return nativeNewFrame[word]
}

// tenantUseArgs is the old `tenant use TENANT`. The old command is gone; the
// fixture sets the tenant of the native context instead.
func tenantUseArgs(args []string) (string, bool) {
	if len(args) == 3 && args[0] == "tenant" && args[1] == "use" {
		return args[2], true
	}
	return "", false
}

func useNativeTenant(ctx context.Context, binary, home, tenant string) ([]byte, []byte, error) {
	name, err := os.ReadFile(filepath.Join(home, ".native-current"))
	if err != nil {
		return nil, nil, fmt.Errorf("tenant use before login: %w", err)
	}
	return runNewFrameCLI(ctx, binary, home, []string{"context", "set", string(name), "--tenant", tenant}, nil, nil)
}

// nativeMovedChange is the new command for a change that left manage apply:
// set-volume-backup-limit and set-volume-capacity.
func nativeMovedChange(id, action string, payload any) ([]string, bool) {
	if strings.HasSuffix(id, "-") {
		id += "cluster" // an old request ID that ended in an empty tenant
	}
	switch action {
	case "set-volume-backup-limit":
		l := payload.(control.VolumeBackupLimit)
		args := []string{"--tenant", l.Tenant}
		if l.Tenant == "" {
			args = nil
		}
		args = append(args, "volume", "backup", "limits", "set", "--node", l.Node, "--id", id,
			"--max-size", fmt.Sprint(l.Bytes), "--max-backups", fmt.Sprint(l.Count),
			"--staging-size", fmt.Sprint(l.StagingBytes), "--staging-backups", fmt.Sprint(l.StagingCount))
		if l.Tenant == "" {
			args = append(args, "--all")
		}
		if l.Original != nil {
			args = append(args, "--volume-size", fmt.Sprint(l.Original.Bytes), "--volumes", fmt.Sprint(l.Original.Count))
		}
		if l.Revision != 0 {
			args = append(args, "--if-revision", fmt.Sprint(l.Revision))
		}
		return args, true
	case "set-volume-capacity":
		c := payload.(control.VolumeCapacity)
		return []string{"--tenant", c.Scope.Tenant, "volume", "resize", c.Scope.App + "/" + c.Scope.ID, "--size", fmt.Sprint(c.Bytes), "--id", id}, true
	}
	return nil, false
}

func legacyLoginArgs(args []string) bool {
	_, word := nativeCommandWord(args)
	return word == "login"
}

const nativeWalletPassword = "private-fixture-wallet-passphrase\n"

func nativeWalletFile(home string) (string, error) {
	file := filepath.Join(home, ".native-wallet-password")
	if _, err := os.Stat(file); err == nil {
		return file, nil
	}
	return file, os.WriteFile(file, []byte(nativeWalletPassword), 0600)
}

func runNewFrameCLI(ctx context.Context, binary, home string, args []string, inputs []*os.File, stdin io.Reader) ([]byte, []byte, error) {
	password, err := nativeWalletFile(home)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.CommandContext(ctx, binary, append([]string{"-o", "json", "-y"}, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+home, "MYDC_WALLET_PASSWORD_FILE="+password, "MYDC_NONINTERACTIVE=1")
	cmd.ExtraFiles = inputs
	cmd.Stdin = stdin
	var output, diagnostic bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	err = cmd.Run()
	return output.Bytes(), diagnostic.Bytes(), err
}

// ensureNativeContext makes (once per user) and selects a context for the
// user the old login just signed in, with the same node and wallet key.
func ensureNativeContext(ctx context.Context, binary, home, profile string, args []string) error {
	var user, keyName, keyFile string
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--username", "--user":
			user = args[i+1]
		case "--key":
			keyName = args[i+1]
		case "--key-file":
			keyFile = args[i+1]
		}
	}
	if user == "" {
		return nil // no username to give a context; such tests use old commands only
	}
	raw, err := os.ReadFile(profile)
	if err != nil {
		return err
	}
	var config struct {
		Peers []struct {
			Key, Endpoint string
			Voter         *bool
		} `yaml:"peers"`
	}
	if err = yaml.Unmarshal(raw, &config); err != nil || len(config.Peers) == 0 {
		return fmt.Errorf("profile peers: %v", err)
	}
	// Only a control voter issues user sessions: prefer the first one.
	peer := config.Peers[0]
	for _, p := range config.Peers {
		if p.Voter == nil || *p.Voter {
			peer = p
			break
		}
	}
	run := func(args ...string) error {
		out, diagnostic, err := runNewFrameCLI(ctx, binary, home, args, nil, nil)
		if err != nil {
			return fmt.Errorf("%v: %v: %s %s", args, err, diagnostic, out)
		}
		return nil
	}
	if keyName == "" {
		keyName = "native-" + user
		if keyFile == "" {
			return nil
		}
		if _, err := os.Stat(filepath.Join(home, ".native-key-"+keyName)); err != nil {
			if err = run("key", "import", keyName, keyFile); err != nil {
				return err
			}
			if err = os.WriteFile(filepath.Join(home, ".native-key-"+keyName), nil, 0600); err != nil {
				return err
			}
		}
	}
	name := "native-" + user
	if _, err := os.Stat(filepath.Join(home, ".native-context-"+name)); err != nil {
		if err = run("--user", user, "context", "add", name, "mydcp://"+peer.Endpoint, "--key", peer.Key, "--wallet-key", keyName); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(home, ".native-context-"+name), nil, 0600); err != nil {
			return err
		}
	}
	if err = run("context", "use", name); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(home, ".native-current"), []byte(name), 0600); err != nil {
		return err
	}
	return run("login")
}

// nativeCLICmd is the exec.Cmd form of runManagedCLICommand for tests that
// read the process result themselves. A login runs right away (old login,
// then the native context); the returned command only reports its result.
func nativeCLICmd(ctx context.Context, binary, home, profile string, args ...string) *exec.Cmd {
	if _, ok := tenantUseArgs(args); ok || legacyLoginArgs(args) || len(args) > 0 && args[0] == "wallet" {
		out, diagnostic, err := runManagedCLICommand(ctx, binary, home, profile, args, nil)
		if err != nil {
			return exec.CommandContext(ctx, "sh", "-c", `printf '%s\n' "$1" >&2; exit 1`, "sh", string(out)+string(diagnostic))
		}
		return exec.CommandContext(ctx, "sh", "-c", `printf '%s' "$1"`, "sh", string(out))
	}
	password, err := nativeWalletFile(home)
	if err != nil {
		return exec.CommandContext(ctx, "sh", "-c", `printf '%s\n' "$1" >&2; exit 1`, "sh", err.Error())
	}
	if newFrameCommand(args) {
		cmd := exec.CommandContext(ctx, binary, append([]string{"-o", "json", "-y"}, args...)...)
		cmd.Env = append(os.Environ(), "HOME="+home, "MYDC_WALLET_PASSWORD_FILE="+password, "MYDC_NONINTERACTIVE=1")
		return cmd
	}
	// The old frame reads the password from fd 3. A shell opens the file
	// itself, so the fixture keeps no descriptor that needs closing.
	shell := append([]string{"-c", `exec "$@" 3<"$0"`, password, binary, "--config", profile, "--wallet-password-fd", "3", "--no-input"}, args...)
	cmd := exec.CommandContext(ctx, "sh", shell...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	return cmd
}

func runLegacyCLICommandInput(ctx context.Context, binary, home, profile string, args []string, inputs []*os.File, stdin io.Reader) ([]byte, []byte, error) {
	extras := append([]*os.File(nil), inputs...)
	defer func() {
		for _, f := range extras[len(inputs):] {
			_ = f.Close()
		}
	}()
	password := func() (int, error) {
		r, w, e := os.Pipe()
		if e != nil {
			return 0, e
		}
		_, e = w.Write([]byte("private-fixture-wallet-passphrase\n"))
		_ = w.Close()
		if e != nil {
			_ = r.Close()
			return 0, e
		}
		extras = append(extras, r)
		return len(extras) + 2, nil
	}
	flags := []string{"--config", profile}
	fd, e := password()
	if e != nil {
		return nil, nil, e
	}
	if len(args) > 0 && args[0] == "wallet" {
		confirm, e := password()
		if e != nil {
			return nil, nil, e
		}
		args = append(append([]string(nil), args...), "--wallet-password-fd", fmt.Sprint(fd), "--wallet-confirm-fd", fmt.Sprint(confirm), "--no-input")
	} else {
		flags = append(flags, "--wallet-password-fd", fmt.Sprint(fd), "--no-input")
	}
	cmd := exec.CommandContext(ctx, binary, append(flags, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.ExtraFiles = extras
	cmd.Stdin = stdin
	var output, diagnostic bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	e = cmd.Run()
	return output.Bytes(), diagnostic.Bytes(), e
}
