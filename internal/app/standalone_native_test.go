// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/moby/moby/client"
)

// The parent prepares this pinned shell-bearing image in the same private
// Engine/rollback baseline. This root never downloads/builds/imports it.
func TestRQ9RealStandaloneShellPinPoliciesAndDaemonRecovery(t *testing.T) {
	if !strings.Contains(os.Getenv("MYDC_TEST_STANDALONE_IMAGE"), "@sha256:") {
		t.Skip("requires explicit pre-provisioned pinned shell image MYDC_TEST_STANDALONE_IMAGE")
	}
	runManagedAppOwner(t, true, true, false, true, managedAppStandalone, true)
}

// Temp/DNS/grace/TTL is retained from native21 and no/always retirement from
// native22. This actual set keeps the original pin/write-layer setup followed
// by on-failure, same-DB recovery and exact manual controls.
func TestRQ9RealStandalonePinnedControlsAndDaemonRecovery(t *testing.T) {
	if !strings.Contains(os.Getenv("MYDC_TEST_STANDALONE_IMAGE"), "@sha256:") {
		t.Skip("requires pre-provisioned pinned shell image")
	}
	runManagedAppOwner(t, true, true, false, true, managedAppStandaloneFixed, true)
}

func TestRQ9RealStandaloneTemporaryExtensionAndOriginalRecovery(t *testing.T) {
	if !strings.Contains(os.Getenv("MYDC_TEST_STANDALONE_IMAGE"), "@sha256:") {
		t.Skip("requires pre-provisioned pinned shell image")
	}
	runManagedAppOwner(t, true, true, false, true, managedAppStandaloneExtend, true)
}

func TestRQ9RealStandaloneQuotaReservationsAndOriginalCleanup(t *testing.T) {
	if !strings.Contains(os.Getenv("MYDC_TEST_STANDALONE_IMAGE"), "@sha256:") {
		t.Skip("requires explicit pre-provisioned pinned shell image MYDC_TEST_STANDALONE_IMAGE")
	}
	runManagedAppOwner(t, true, true, false, true, managedAppStandaloneQuota, true)
}

func prepareStandaloneUserNative(t *testing.T, ctx context.Context, r *Runtime, root string, user userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), manifest map[string]any, saveManifest func(), quotaOnly, fixedOnly, extendOnly bool) func(*Runtime) {
	t.Helper()
	image := os.Getenv("MYDC_TEST_STANDALONE_IMAGE")
	imageBefore, err := r.docker.API.ImageInspect(ctx, image)
	if err != nil {
		t.Fatal("standalone shell input must already exist in this private Engine", err)
	}
	var imageVolumes, tmpfsInput []string
	for target := range imageBefore.Config.Volumes {
		imageVolumes = append(imageVolumes, target)
	}
	slices.Sort(imageVolumes)
	for _, target := range imageVolumes {
		tmpfsInput = append(tmpfsInput, fmt.Sprintf("%q", target+":size=1m,uid=1000,gid=1000,mode=0700"))
	}
	entrypoint, command := []string{"/bin/sh"}, []string{"-i"}
	if _, err = workload.ResolveImageProcess(imageBefore, workload.ProcessOverrides{Entrypoint: &entrypoint, Command: &command, User: "1000:1000", MountTargets: imageVolumes}); err != nil {
		t.Fatal("pre-provisioned shell image/config and declared image-volume mounts", err)
	}
	manifest["BorrowedImages"] = []string{image}
	saveManifest()
	cli := &fixedAppNativeFixture{home: filepath.Join(root, "cli-home"), profile: filepath.Join(root, "cli.yaml"), binary: os.Getenv("MYDC_TEST_CLI")}
	call := func(want int, args ...string) map[string]json.RawMessage {
		return cli.cli(t, ctx, want, append([]string{"--tenant", "tenant"}, args...)...)
	}
	prefix := netip.MustParsePrefix(os.Getenv("MYDC_DOCKER_TEST_CIDR"))
	address := func(offset int) string {
		a := prefix.Addr()
		for i := 0; i < offset; i++ {
			a = a.Next()
		}
		if !prefix.Contains(a) {
			t.Fatal("owned CIDR needs room for explicit standalone input addresses")
		}
		return a.String()
	}
	var dnsName string
	if !quotaOnly && !fixedOnly {
		wait("current app service DNS for standalone shell", func() bool {
			apps, err := p.Apps(read().State)
			if err != nil || r.dnsOwner() == nil {
				return false
			}
			_, rows, ok := apps.NetworkDNS(r.Identity.Public)
			if !ok {
				return false
			}
			for _, row := range rows {
				material, _, err := p.AppDNSMaterial(read().State, r.Identity.Public, "tenant", row.Config.ID)
				if err != nil || !r.dnsOwner().Status(row.Config.Tenant, row.Config.ID).Ready {
					continue
				}
				for _, record := range material.Config.Names {
					allocation, found := material.Authority.AddressBook().Allocation(record.Endpoint)
					if found && strings.HasPrefix(record.Name, "web.") && allocation.Address.String() == address(2) {
						dnsName = record.Name
						return true
					}
				}
			}
			return false
		})
	}
	definition := func(name string, offset int, imageRef string) string {
		t.Helper()
		dnsInput := ""
		if !quotaOnly && !fixedOnly {
			dnsInput = fmt.Sprintf("  dns: [%s]\n", address(1))
		}
		body := fmt.Sprintf("services:\n debug:\n  image: %q\n  entrypoint: [/bin/sh]\n  command: [-i]\n  user: '1000:1000'\n  cpus: '0.01'\n  mem_limit: 16m\n  stdin_open: true\n  tty: true\n  tmpfs: [%s]\n  networks: {lan: {ipv4_address: %s}}\n%s  logging: {driver: local, options: {max-size: 16k, max-file: '2'}}\n  healthcheck: {test: [CMD, /bin/sh, -c, 'exit 0'], interval: 1s, timeout: 1s, retries: 2}\n  x-mydc: {node: node-a}\nnetworks:\n lan: {external: true, name: shared-services}\n", imageRef, strings.Join(tmpfsInput, ", "), address(offset), dnsInput)
		file := filepath.Join(root, "standalone-"+name+".yaml")
		if err := os.WriteFile(file, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	page := func(name string) control.StandaloneView {
		t.Helper()
		reply, err := user.StandalonePage(ctx, peer, session, "tenant", name, "")
		if err != nil || len(reply.Standalones) != 1 {
			t.Fatal("standalone original page", name, err)
		}
		return reply.Standalones[0]
	}
	running := func(name string) containerops.Target {
		t.Helper()
		var target containerops.Target
		wait("actual standalone owner/Task/native "+name, func() bool {
			var e error
			target, e = user.ResolveContainerSession(ctx, peer, session, "tenant", containerops.Selection{Standalone: name}, containerops.SessionSpec{Kind: "attach", Exec: &containerops.ExecSpec{Stdin: true, TTY: true, Rows: 24, Cols: 80}})
			if e != nil {
				return false
			}
			got, e := r.docker.API.ContainerInspect(ctx, target.NativeID, client.ContainerInspectOptions{})
			// Session resolution pins the committed observation. Native Running alone
			// does not prove its post-restart StartedAt has been reported yet.
			return e == nil && got.Container.State != nil && got.Container.State.Running && got.Container.State.StartedAt == target.StartedAt
		})
		return target
	}
	gone := func(name, reason string) {
		t.Helper()
		wait("original standalone retirement "+name, func() bool {
			v := page(name)
			apps, e := p.Apps(read().State)
			inventory, ok := apps.Inventory("tenant", v.Metadata.Scope)
			if e != nil || !ok || !inventory.Quiescent() {
				return false
			}
			if reason != "" && (v.Metadata.Cleanup == nil || v.Metadata.Cleanup.Reason != reason) {
				return false
			}
			closed, e := r.docker.Gone(ctx, "container", deployment.ResourceKey("task", "tenant", v.Metadata.Scope, "debug"))
			return e == nil && closed
		})
	}
	if quotaOnly {
		verifyStandaloneQuotaReservations(t, image, definition, call, gone, func(file string) {
			body, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			_, err = user.PlanApp(ctx, peer, session, "tenant", control.AppPlanRequest{Project: "quota-over", Document: body, Standalone: &control.StandaloneDefinition{Name: "quota-over", Mode: "shell"}})
			var input *deployment.InputError
			if !errors.As(err, &input) || input.Code != "STANDALONE_USER_LIMIT" {
				t.Fatal("ninth standalone did not reach the distinct current user quota refusal", err)
			}
		})
		imageAfter, err := r.docker.API.ImageInspect(ctx, image)
		if err != nil || imageAfter.ID != imageBefore.ID {
			t.Fatal("standalone quota fixture mutated borrowed pinned image cache", err)
		}
		// Every quota original has already retired. The common fixture retains
		// its own app Close/Open and rollback without repeating shell recovery.
		return func(*Runtime) {}
	}
	open := func(name, id string) (*userauth.ContainerChannel, containerops.Target) {
		t.Helper()
		spec := containerops.SessionSpec{Kind: "attach", Exec: &containerops.ExecSpec{Stdin: true, TTY: true, Rows: 24, Cols: 80}}
		target, err := user.ResolveContainerSession(ctx, peer, session, "tenant", containerops.Selection{Standalone: name}, spec)
		if err != nil {
			t.Fatal(err)
		}
		intent := containerops.SessionIntent{Schema: 1, Request: id, User: session.User, Session: access.ExactSessionDigest(session), At: time.Now().Unix(), Target: target, Spec: spec}
		intent.Signature = ed25519.Sign(user.Self.Private, containerops.SessionIntentBytes(intent))
		ch, err := user.OpenContainerSession(ctx, peer, session, intent, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ch.Close() })
		return ch, target
	}
	shell := func(ch *userauth.ContainerChannel, command, marker string) string {
		t.Helper()
		if err := ch.Send(containerops.SessionRecord{Kind: "stdin", Data: []byte(command + "\n")}); err != nil {
			t.Fatal(err)
		}
		var out nativeSessionOutput
		out.receive(t, ch, func(containerops.SessionRecord) bool { return strings.Contains(out.stdout.String(), marker) })
		return out.stdout.String()
	}
	markerLine := func(output, marker string) string {
		t.Helper()
		for _, line := range strings.Split(strings.ReplaceAll(output, "\r", ""), "\n") {
			if i := strings.Index(line, marker); i >= 0 {
				return line[i:]
			}
		}
		t.Fatal("shell output marker absent")
		return ""
	}

	initialTTL, initialGrace := "120", "10"
	if extendOnly {
		initialTTL, initialGrace = "3600", "600"
	}
	file := definition("shell", 3, image)
	planned := call(0, "standalone", "plan", "debug", "-f", file, "--mode", "shell", "--lifetime", "temp", "--ttl-seconds", initialTTL, "--grace-seconds", initialGrace)
	if string(planned["InputKind"]) != `"standalone"` || string(planned["Schema"]) != "1" {
		t.Fatal("standalone plan omitted actual artifact", planned)
	}
	call(0, "standalone", "up", "debug", "-f", file, "--mode", "shell", "--lifetime", "temp", "--ttl-seconds", initialTTL, "--grace-seconds", initialGrace, "--operation", "debug-create")
	first := running("debug")
	firstView := page("debug")
	removal, err := p.PlanNodeRemoval(read().State, session, time.Now().Unix(), first.Node)
	if err != nil {
		t.Fatal("standalone removal plan", err)
	}
	standaloneBlocked := false
	for _, task := range removal.Tasks {
		if task.Task == first.Instance && task.Standalone == "debug" && !task.Movable && task.Reason == "STANDALONE_WRITABLE_LAYER_PRESENT" {
			standaloneBlocked = true
		}
	}
	if !standaloneBlocked || removal.Removable {
		t.Fatal("live standalone/writable layer omitted from removal plan")
	}
	// The real CLI writes through purpose15, then SIGTERM disconnects only that
	// client connection. It neither sends shell EOF nor controls the container.
	output := standaloneCLIAttachMarker(t, ctx, cli, "debug", "cli-first", "printf layer-proof > /tmp/rq9-layer; printf 'rq9-%s:%s\\n' 'first' \"$$\"", "rq9-first:", func() {
		wait("owner observed real CLI connection", func() bool { return page("debug").Metadata.Connections > 0 })
	})
	pid := strings.TrimPrefix(markerLine(output, "rq9-first:"), "rq9-first:")
	if pid == "" {
		t.Fatal("real shell did not return PID")
	}
	same := running("debug")
	if same.NativeID != first.NativeID || same.StartedAt != first.StartedAt {
		t.Fatal("CLI disconnect restarted/replaced shell")
	}
	reconnected, target := open("debug", "reconnect-original")
	output = shell(reconnected, "IFS= read -r proof < /tmp/rq9-layer; printf 'rq9-%s:%s:%s\\n' 'again' \"$$\" \"$proof\"", "rq9-again:")
	if markerLine(output, "rq9-again:") != "rq9-again:"+pid+":layer-proof" || !target.Matches(first) {
		t.Fatal("reconnect did not preserve original process/write layer")
	}
	if !fixedOnly {
		output = shell(reconnected, fmt.Sprintf("if /bin/busybox nslookup %q; then printf 'rq9-%%s:ok\\n' 'dns'; else printf 'rq9-%%s:failed\\n' 'dns'; fi", dnsName), "rq9-dns:")
		if markerLine(output, "rq9-dns:") != "rq9-dns:ok" || !strings.Contains(output, address(2)) {
			t.Fatal("real standalone shell could not resolve original app service", dnsName, output)
		}
		t.Log("original shell attach/reconnect preserves process and writable layer; actual app service DNS succeeds")
		var ownDNS string
		wait("omitted standalone alias publishes original public name", func() bool {
			apps, e := p.Apps(read().State)
			if e != nil {
				return false
			}
			_, rows, ok := apps.NetworkDNS(r.Identity.Public)
			if !ok || r.dnsOwner() == nil {
				return false
			}
			for _, row := range rows {
				material, _, err := p.AppDNSMaterial(read().State, r.Identity.Public, "tenant", row.Config.ID)
				if err != nil || !r.dnsOwner().Status(row.Config.Tenant, row.Config.ID).Ready {
					continue
				}
				for _, record := range material.Config.Names {
					allocation, found := material.Authority.AddressBook().Allocation(record.Endpoint)
					if found && record.Name == "debug."+material.Config.Zone && allocation.Address.String() == address(3) {
						ownDNS = record.Name
						return true
					}
				}
			}
			return false
		})
		output = shell(reconnected, fmt.Sprintf("/bin/busybox nslookup %q; printf 'rq9-%%s:done\\n' 'own-dns'", ownDNS), "rq9-own-dns:")
		if !strings.Contains(output, address(3)) {
			t.Fatal("default standalone name did not resolve to original Task")
		}
		t.Log("original standalone public DNS alias resolves:", ownDNS)
	}
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	inventory, _ := apps.Inventory("tenant", firstView.Metadata.Scope)
	beforeExecution, _ := inventory.Execution()
	beforeBlueprint := beforeExecution.Blueprint().Digest()
	beforeTask, _ := beforeExecution.Stage(first.Instance)
	if extendOnly {
		extend := func(name, operation string, ttl int64, want int) control.StandaloneExtensionPlan {
			t.Helper()
			out := call(want, "standalone", "extend", name, "--ttl-seconds", fmt.Sprint(ttl), "--operation", operation)
			var plan control.StandaloneExtensionPlan
			if raw := out["extension"]; len(raw) > 0 {
				if json.Unmarshal(raw, &plan) != nil {
					t.Fatal("extension numeric result shape")
				}
			}
			if want == 0 && (string(out["extension_applied"]) != "true" || plan.ProposedExpiresAt != plan.At+ttl || plan.MaximumExpiresAt != firstView.Metadata.CreatedAt+86400) {
				t.Fatal("extension did not report original accepted bounds")
			}
			return plan
		}
		plan := extend("debug", "extend-first", 7200, 0)
		after := page("debug")
		if after.Metadata.ExpiresAt != plan.ProposedExpiresAt || after.Metadata.CreatedAt != firstView.Metadata.CreatedAt || after.Metadata.GraceSeconds != firstView.Metadata.GraceSeconds || after.RemainingSeconds <= 3600 || after.Target == firstView.Target {
			t.Fatal("extension changed original policy or did not update TTL/target")
		}
		checkOriginal := func(name string) {
			t.Helper()
			current := running(name)
			apps, e := p.Apps(read().State)
			x, ok := apps.Execution("tenant", firstView.Metadata.Scope)
			stage, found := x.Stage(first.Instance)
			if e != nil || !ok || !found || x.Blueprint().Digest() != beforeBlueprint || stage.Result == nil || beforeTask.Result == nil || *stage.Result != *beforeTask.Result || current.NativeID != first.NativeID || current.StartedAt != first.StartedAt {
				t.Fatal("extension replaced original Task/native/blueprint")
			}
		}
		checkOriginal("debug")
		replayed := extend("debug", "extend-first", 7200, 0)
		if replayed != plan {
			t.Fatal("extension replay changed original coordinates")
		}
		limit := extend("debug", "extend-limit", 86400, 3)
		if limit.AllowedTTLSeconds <= 0 || limit.AllowedTTLSeconds >= 86400 || page("debug").Metadata.ExpiresAt != plan.ProposedExpiresAt {
			t.Fatal("24 hour limit refused without numeric allowance or changed expiry")
		}
		extend("debug", "extend-short", 1, 3)
		checkOriginal("debug")
		unixPath := filepath.Join(root, "standalone-extension.sock")
		if err := r.Mesh.ListenUnix(unixPath); err != nil {
			t.Fatal(err)
		}
		unixPeer := peer
		unixPeer.Endpoint = "unix://" + unixPath
		local := user
		local.Mesh, err = mydcp.NewTransport(user.Self, user.Cluster, func(key mydcp.Identity) (mydcp.Peer, bool) { return unixPeer, key == unixPeer.Key })
		if err != nil {
			t.Fatal("create exact pinned Unix client", err)
		}
		defer local.Mesh.Close()
		local.Peers = []mydcp.Peer{unixPeer}
		current := page("debug")
		unixChange := control.StandaloneExtendChange{Tenant: "tenant", Name: "debug", Scope: current.Metadata.Scope, Operation: "extend-unix", CreatedAt: current.Metadata.CreatedAt, PreviousExpiresAt: current.Metadata.ExpiresAt, TTLSeconds: 8000, Target: current.Target}
		unixRaw, _ := control.ChangeBytes("standalone-extend", session.User, current.Metadata.Revision, unixChange)
		var unixTyped control.Change
		_ = json.Unmarshal(unixRaw, &unixTyped)
		unixOriginal, e := local.Prepare(ctx, unixPeer, session, "standalone/extend/tenant/extend-unix", unixTyped)
		if e != nil {
			t.Fatal("prepare exact pinned Unix extension", e)
		}
		if _, e = userauth.StageOperation(cli.home, local, unixOriginal); e != nil {
			t.Fatal(e)
		}
		unixResult, e := local.Operation(ctx, unixPeer, unixOriginal, false)
		if e != nil || !unixResult.Found || unixResult.Result == nil || unixResult.Result.Code != state.Applied || unixResult.StandaloneExtension == nil {
			t.Fatal("actual Unix extension not accepted", e)
		}
		unixPlan := *unixResult.StandaloneExtension
		if e = userauth.RecordOperationResult(cli.home, local, session, unixOriginal, *unixResult.Result); e != nil {
			t.Fatal(e)
		}
		if unixPlan.ProposedExpiresAt <= plan.ProposedExpiresAt || page("debug").Metadata.ExpiresAt != unixPlan.ProposedExpiresAt {
			t.Fatal("Unix extension did not update same original")
		}
		checkOriginal("debug")
		// A signed foreign-tenant request reaches the real service, rather than
		// only exercising the CLI's local selected-tenant guard.
		foreign := control.StandaloneExtendChange{Tenant: "foreign", Name: "debug", Scope: after.Metadata.Scope, Operation: "extend-foreign", CreatedAt: after.Metadata.CreatedAt, PreviousExpiresAt: after.Metadata.ExpiresAt, TTLSeconds: 8000, Target: after.Target}
		raw, _ := control.ChangeBytes("standalone-extend", session.User, after.Metadata.Revision, foreign)
		var change control.Change
		_ = json.Unmarshal(raw, &change)
		original, e := user.Prepare(ctx, peer, session, "standalone/extend/foreign/extend-foreign", change)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = userauth.StageOperation(cli.home, user, original); e != nil {
			t.Fatal(e)
		}
		if result, e := user.Operation(ctx, peer, original, false); e == nil || result.Found {
			t.Fatal("foreign tenant extension not refused")
		}
		_ = reconnected.Close()
		t.Log("original running temp extended with CLI/wire numeric cap/refusal, Task/native and grace preserved")
		return func(next *Runtime) {
			r = next
			checkOriginal("debug")
			if page("debug").Metadata.ExpiresAt != unixPlan.ProposedExpiresAt {
				t.Fatal("same DB lost extended expiry")
			}
			channel, _ := open("debug", "extended-after-reopen")
			out := shell(channel, "IFS= read -r proof < /tmp/rq9-layer; printf 'rq9-%s:%s:%s\n' 'extended' \"$$\" \"$proof\"", "rq9-extended:")
			if markerLine(out, "rq9-extended:") != "rq9-extended:"+pid+":layer-proof" {
				t.Fatal("extension or same DB lost original PID/write layer")
			}
			_ = channel.Close()
			call(0, "standalone", "pin", "debug", "--name", "kept", "--operation", "extend-pin")
			call(3, "standalone", "extend", "kept", "--ttl-seconds", "3600", "--operation", "extend-fixed")
			// Generic result crosses the User service after pin; original arithmetic
			// must not become the fixed policy's zero expiry or current metadata.
			old, e := userauth.LoadOperation(cli.home, user, session, "standalone/extend/tenant/extend-first")
			if e != nil {
				t.Fatal(e)
			}
			result, e := user.Result(ctx, peer, session, old.Operation)
			if e != nil || result.Result == nil || result.Result.Code != state.Applied || result.StandaloneExtension == nil || *result.StandaloneExtension != plan {
				t.Fatal("wire original extension result changed after pin", e)
			}
			call(0, "standalone", "remove", "kept", "--operation", "extended-remove")
			call(3, "standalone", "extend", "kept", "--ttl-seconds", "3600", "--operation", "extend-cleanup")
			gone("kept", "")
			t.Log("extended original survives same DB/pin; fixed/cleanup refused and original native retired")
		}
	}
	call(0, "standalone", "pin", "debug", "--name", "kept", "--restart", "on-failure", "--operation", "pin-debug")
	kept := page("kept")
	apps, err = p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	inventory, _ = apps.Inventory("tenant", kept.Metadata.Scope)
	afterExecution, _ := inventory.Execution()
	afterTask, _ := afterExecution.Stage(first.Instance)
	if kept.Metadata.Scope != firstView.Metadata.Scope || kept.Metadata.Lifetime != "fixed" || beforeBlueprint != afterExecution.Blueprint().Digest() || beforeTask.Result == nil || afterTask.Result == nil || *beforeTask.Result != *afterTask.Result {
		t.Fatal("pin changed original workload inventory")
	}
	output = shell(reconnected, "printf 'rq9-%s:%s\\n' 'pinned' \"$$\"", "rq9-pinned:")
	if markerLine(output, "rq9-pinned:") != "rq9-pinned:"+pid {
		t.Fatal("public rename replaced active shell")
	}
	_ = reconnected.Close()
	wait("fixed connection metadata after disconnect", func() bool { return page("kept").Metadata.Connections == 0 })
	call(0, "standalone", "get", "kept")
	currentKept := page("kept")
	if len(currentKept.Tasks) != 1 || currentKept.Tasks[0].Kind != "standalone" || currentKept.Tasks[0].Standalone != "kept" || currentKept.Tasks[0].App != "" || currentKept.Tasks[0].Container != first.NativeID {
		t.Fatal("standalone get did not reuse explicit-kind Task projection")
	}
	if !fixedOnly {
		ordinaryApps, err := user.Query(ctx, peer, session, "apps", "tenant")
		if err != nil || len(ordinaryApps.Apps) != 1 || ordinaryApps.Apps[0].App != "app" {
			t.Fatal("ordinary app list mixed standalone owners", err)
		}
		for _, kind := range []string{"logs", "top", "stats", "inspect"} {
			result := call(0, "standalone", kind, "kept", "--json")
			var actual containerops.Target
			if json.Unmarshal(result["Target"], &actual) != nil || actual.NativeID != first.NativeID || actual.Standalone != "kept" {
				t.Fatal("standalone did not use common observation target", kind)
			}
		}
		// Ordinary app reads/down and app source compilation cannot adopt the explicit
		// standalone kind by its public name or guessed internal workload scope.
		ordinary, err := user.StandalonePage(ctx, peer, session, "tenant", "app", "")
		if err != nil || len(ordinary.Standalones) != 0 {
			t.Fatal("ordinary app was adopted as standalone", err)
		}
		call(-1, "compose", "down", "-p", kept.Metadata.Scope, "--operation", "deny-app-down")
		originalBody, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = user.PlanApp(ctx, peer, session, "tenant", control.AppPlanRequest{Project: kept.Metadata.Scope, Document: originalBody}); err == nil {
			t.Fatal("ordinary app plan adopted standalone internal scope")
		}
		untrusted := definition("untrusted", 14, "untrusted.invalid/fixture@sha256:"+strings.Repeat("a", 64))
		call(-1, "standalone", "plan", "untrusted", "-f", untrusted, "--mode", "shell")
		change("rq9-foreign-tenant", "create-tenant", 0, control.TenantID{ID: "foreign"})
		limited := session
		limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read, access.Deploy}}}
		limited.Signature = ed25519.Sign(r.Identity.Private, access.SessionBytes(limited))
		if _, err = user.StandalonePage(ctx, peer, limited, "foreign", "kept", ""); err == nil {
			t.Fatal("tenant-scoped User read exposed foreign standalone")
		}
		if _, err = user.ObserveContainer(ctx, peer, limited, "foreign", containerops.Query{Schema: 1, Selection: containerops.Selection{Standalone: "kept"}, Kind: "top", MaxBytes: 1024}); err == nil {
			t.Fatal("foreign tenant native observation accepted")
		}

		graceFile := definition("grace", 4, image)
		call(0, "standalone", "up", "grace", "-f", graceFile, "--mode", "shell", "--ttl-seconds", "120", "--grace-seconds", "2", "--operation", "grace-create")
		_ = running("grace")
		call(-1, "standalone", "pin", "grace", "--name", "kept", "--operation", "deny-name-collision")
		viewerKey, err := identity.Create(filepath.Join(root, "standalone-viewer"))
		if err != nil {
			t.Fatal(err)
		}
		defer clear(viewerKey.Private)
		change("rq9-standalone-viewer", "put-user", 0, access.User{ID: "standalone-viewer", Username: "standalone-viewer", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: viewerKey.Public, Enabled: true}}})
		change("rq9-standalone-viewer-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: "standalone-viewer", Role: access.Viewer, Enabled: true})
		viewer, err := user.Login(ctx, peer, "standalone-viewer", viewerKey.Private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = user.ResolveContainerSession(ctx, peer, viewer, "tenant", containerops.Selection{Standalone: "grace"}, containerops.SessionSpec{Kind: "attach", Exec: &containerops.ExecSpec{Stdin: true, TTY: true, Rows: 24, Cols: 80}}); err == nil {
			t.Fatal("another user's temp attached with Read only")
		}
		protected := page("grace")
		removeBytes, err := control.ChangeBytes("standalone-remove", viewer.User, protected.Metadata.Revision, control.StandaloneChange{Tenant: "tenant", Name: "grace", Operation: "foreign-remove"})
		if err != nil {
			t.Fatal(err)
		}
		var removeChange control.Change
		if err = json.Unmarshal(removeBytes, &removeChange); err != nil {
			t.Fatal(err)
		}
		forbidden, err := user.Prepare(ctx, peer, viewer, "rq9-foreign-remove", removeChange)
		if err != nil {
			t.Fatal(err)
		}
		rejected, err := user.Operation(ctx, peer, forbidden, false)
		if err == nil && (rejected.Result == nil || rejected.Result.Code == state.Applied) {
			t.Fatal("another user's temp was removed")
		}
		_ = standaloneCLIAttachMarker(t, ctx, cli, "grace", "grace-connection", "printf 'rq9-%s\\n' 'grace'", "rq9-grace", func() {
			wait("grace connection observed", func() bool { return page("grace").Metadata.Connections > 0 })
		})
		gone("grace", "disconnected")
		t.Log("original grace policy retired its exact Task and native container")
		ttlFile := definition("ttl", 5, image)
		call(0, "standalone", "up", "ttl", "-f", ttlFile, "--mode", "shell", "--ttl-seconds", "30", "--grace-seconds", "1", "--operation", "ttl-create")
		_ = running("ttl")
		gone("ttl", "ttl")
		t.Log("original TTL policy removed an actually running Task")
	}
	if !fixedOnly {
		for _, policy := range []string{"no", "always"} {
			t.Log("fixed original restart policy", policy)
			name := "fixed-" + policy
			file := definition(name, 4, image)
			call(0, "standalone", "up", name, "-f", file, "--mode", "shell", "--lifetime", "fixed", "--restart", policy, "--operation", name+"-create")
			original := running(name)
			channel, _ := open(name, name+"-connection")
			code := 7
			if policy == "always" {
				code = 0
			}
			if err := channel.Send(containerops.SessionRecord{Kind: "stdin", Data: []byte(fmt.Sprintf("exit %d\n", code))}); err != nil {
				t.Fatal(err)
			}
			var closed nativeSessionOutput
			closed.receive(t, channel, func(record containerops.SessionRecord) bool { return record.Kind == "end" || record.Kind == "error" })
			_ = channel.Close()
			if policy == "always" {
				wait("fixed always restarts clean exit on original native", func() bool {
					got, err := r.docker.API.ContainerInspect(ctx, original.NativeID, client.ContainerInspectOptions{})
					return err == nil && got.Container.State != nil && got.Container.State.Running && got.Container.State.StartedAt != original.StartedAt
				})
			} else {
				wait("fixed no actual exit observation", func() bool {
					view := page(name)
					for _, task := range view.Tasks {
						if task.Container == original.NativeID && task.ExitCode != nil && *task.ExitCode == 7 {
							return true
						}
					}
					return false
				})
				observedAt := page(name).Metadata.ConnectionAt
				wait("fixed no another owner policy sample", func() bool { return page(name).Metadata.ConnectionAt > observedAt })
				got, err := r.docker.API.ContainerInspect(ctx, original.NativeID, client.ContainerInspectOptions{})
				if err != nil || got.Container.State == nil || got.Container.State.Running || got.Container.State.StartedAt != original.StartedAt {
					t.Fatal("fixed no restarted/replaced original", err)
				}
			}
			call(0, "standalone", "remove", name, "--operation", name+"-remove")
			gone(name, "")
			t.Log("fixed policy original retired", policy)
		}
	}
	// Leave precisely the pinned original alive for the existing managed fixture's
	// snapshot/Close/Open. No additional daemon launcher or synthetic start fact.
	beforeReopen := running("kept")
	return func(next *Runtime) {
		r = next
		after := running("kept")
		if after.NativeID != beforeReopen.NativeID || after.StartedAt != beforeReopen.StartedAt || after.Instance != first.Instance {
			t.Fatal("daemon reopen replaced pinned original process")
		}
		channel, _ := open("kept", "after-daemon-reopen")
		out := shell(channel, "IFS= read -r proof < /tmp/rq9-layer; printf 'rq9-%s:%s:%s\\n' 'reopened' \"$$\" \"$proof\"", "rq9-reopened:")
		if markerLine(out, "rq9-reopened:") != "rq9-reopened:"+pid+":layer-proof" {
			t.Fatal("daemon reopen lost process/write layer")
		}
		if err := channel.Send(containerops.SessionRecord{Kind: "stdin", Data: []byte("exit 7\n")}); err != nil {
			t.Fatal(err)
		}
		var exited nativeSessionOutput
		exited.receive(t, channel, func(record containerops.SessionRecord) bool { return record.Kind == "end" || record.Kind == "error" })
		_ = channel.Close()
		wait("fixed on-failure restarts same exact native", func() bool {
			got, err := r.docker.API.ContainerInspect(ctx, after.NativeID, client.ContainerInspectOptions{})
			return err == nil && got.Container.State != nil && got.Container.State.Running && got.Container.State.StartedAt != after.StartedAt
		})
		restarted := running("kept")
		if restarted.NativeID != first.NativeID {
			t.Fatal("fixed policy created replacement native")
		}
		t.Log("on-failure original native restart and committed StartedAt converged")
		channel, _ = open("kept", "after-policy-restart")
		out = shell(channel, "IFS= read -r proof < /tmp/rq9-layer; printf 'rq9-%s:%s\\n' 'restart' \"$proof\"", "rq9-restart:")
		if markerLine(out, "rq9-restart:") != "rq9-restart:layer-proof" {
			t.Fatal("fixed restart lost writable layer")
		}
		_ = channel.Close()
		for _, action := range []string{"stop", "start", "restart"} {
			t.Log("original standalone manual control", action)
			operation := "control-" + action
			call(0, "standalone", action, "kept", "--preview")
			call(0, "standalone", action, "kept", "--operation", operation)
			wait("common original Task control "+action, func() bool {
				apps, err := p.Apps(read().State)
				status := apps.TaskRestartStatus("tenant", kept.Metadata.Scope, operation)
				if status != nil && status.Status == "canceled" {
					t.Fatal("original manual control canceled before completion", action)
				}
				return err == nil && status != nil && status.Status == "completed"
			})
			call(0, "standalone", "control-status", "kept", "--operation", operation)
			got, err := r.docker.API.ContainerInspect(ctx, first.NativeID, client.ContainerInspectOptions{})
			if err != nil || got.Container.State == nil || (got.Container.State.Running != (action != "stop")) {
				t.Fatal("common native control target/state", action, err)
			}
			if action != "stop" {
				// A completed SDK control can precede its new Task observation.
				// The next control must sign the newly committed incarnation.
				current := running("kept")
				if current.NativeID != first.NativeID || current.StartedAt != got.Container.State.StartedAt {
					t.Fatal("manual control did not converge on original new incarnation", action)
				}
			}
		}
		call(0, "standalone", "remove", "kept", "--operation", "kept-remove")
		gone("kept", "")
		imageAfter, err := r.docker.API.ImageInspect(ctx, image)
		if err != nil || imageAfter.ID != imageBefore.ID {
			t.Fatal("standalone mutated borrowed pinned image cache", err)
		}
	}
}

// verifyStandaloneQuotaReservations consumes the same original CLI, explicit
// definitions and retirement observer as the shell fixture. It deliberately
// performs no attach, DNS, TTL or restart-policy checks.
func verifyStandaloneQuotaReservations(t *testing.T, image string, definition func(string, int, string) string, call func(int, ...string) map[string]json.RawMessage, gone func(string, string), refuse func(string)) {
	t.Helper()
	// Exercise the actual user quota through eight separately accepted original
	// workloads. Global/tenant Task capacity is explicit fixture input, not raised
	// in response to failure. Other quota dimensions reuse their existing core roots.
	for i := 0; i < control.StandaloneTempLimitUser; i++ {
		name := fmt.Sprintf("quota-%d", i)
		f := definition(name, 6+i, image)
		call(0, "standalone", "up", name, "-f", f, "--mode", "shell", "--ttl-seconds", "3600", "--operation", name+"-create")
	}
	quotaOver := definition("quota-over", 14, image)
	refuse(quotaOver)
	call(-1, "standalone", "plan", "quota-over", "-f", quotaOver, "--mode", "shell")
	for i := 0; i < control.StandaloneTempLimitUser; i++ {
		name := fmt.Sprintf("quota-%d", i)
		call(0, "standalone", "remove", name, "--operation", name+"-remove")
		gone(name, "")
	}
	t.Log("eight real user-quota reservations rejected the ninth and retired original operations")
}

// One asynchronous invocation of the existing prebuilt CLI is required to
// disconnect a live stdin connection without sending EOF to the shell.
func standaloneCLIAttachMarker(t *testing.T, ctx context.Context, cli *fixedAppNativeFixture, name, id, command, marker string, connected func()) string {
	t.Helper()
	password, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer password.Close()
	_, err = io.WriteString(writer, "private-fixture-wallet-passphrase\n")
	_ = writer.Close()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, cli.binary, "--config", cli.profile, "--wallet-password-fd", "3", "--no-input", "--tenant", "tenant", "standalone", "attach", name, "--operation", id, "-it")
	child.Env = append(os.Environ(), "HOME="+cli.home)
	child.ExtraFiles = []*os.File{password}
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	var output sessionCLIOutput
	child.Stdout, child.Stderr = &output, &output
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	waited := false
	defer func() {
		if !waited {
			_ = child.Process.Kill()
			<-done
		}
	}()
	if _, err = io.WriteString(input, command+"\n"); err != nil {
		t.Fatal(err)
	}
	for !output.contains(marker) {
		select {
		case err := <-done:
			waited = true
			t.Fatal("standalone CLI ended before shell output", err, output.text())
		case <-ctx.Done():
			t.Fatal("standalone CLI marker", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	connected()
	if err = child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		waited = true
	case <-ctx.Done():
		t.Fatal("standalone CLI disconnect join", ctx.Err())
	}
	if output.contains("private-fixture-wallet-passphrase") {
		t.Fatal("wallet password reached terminal output")
	}
	return output.text()
}
