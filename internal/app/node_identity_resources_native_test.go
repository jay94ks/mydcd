// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/bootstrap"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/desired"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload"
	volumeapi "github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/jay94ks/mydcd/tests/vaultfixture"
	"github.com/moby/moby/client"
)

func TestRealBoundaryInstalledIdentityNewDeploymentRetainsVolumeNetworkAndSecret(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppIdentityRotation, true, true, true)
}

// Reuses native24 diagnostics admission/output/revocation evidence while this
// exact same original native fixture spends its bounded envelope on final down.
func TestRQ12RetainedIdentityResourcesReachFinalClosure(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppIdentityClosure, true, true, true)
}

// This uses the existing owned native fixture and prebuilt CLI. It never
// manufactures a Task closure, Volume fence, provider approval or native ID.
func verifyManagedIdentityResources(t *testing.T, ctx context.Context, runtime **Runtime, cfg config.Node, root string, user *userauth.Client, peer *mydcp.Peer, session *access.Session, admin ed25519.PrivateKey, policy control.Policy, read func() cluster.View, wait func(string, func() bool), vault *vaultfixture.Vault, manifest map[string]any, saveManifest func(), groups []string, compiled ...bool) {
	t.Helper()
	// Capture every original native owner's first error before the enclosing
	// fixture closes its runtimes. Root-only errors can hide a retained
	// Volume/DNS/Ingress consumer that blocked a current-key dependency.
	t.Cleanup(func() {
		if !t.Failed() || *runtime == nil {
			return
		}
		for _, owner := range (*runtime).physicalOwners() {
			owner.mu.RLock()
			moduleError, reportError := owner.moduleError, owner.reportError
			owner.mu.RUnlock()
			t.Logf("identity native owner failure owner=%x historical=%t module=%v report=%v", owner.Identity.Public, owner.historicalOwner, moduleError, reportError)
		}
	})
	taskKey := deployment.ResourceKey("task", "tenant", "app", "web")
	stage := func() deployment.StageRecord {
		a, err := policy.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		e, _ := a.Execution("tenant", "app")
		s, _ := e.Stage(taskKey)
		return s
	}
	wait("original native app before identity replacement", func() bool {
		a, err := policy.Apps(read().State)
		e, ok := a.Execution("tenant", "app")
		s := stage()
		return err == nil && ok && e.Status() == "Succeeded" && s.Observation != nil && s.Observation.Healthy
	})
	compile := len(compiled) != 0 && compiled[0]
	closureOnly := len(compiled) > 1 && compiled[1]
	var compiledProof *identityCompiledProof
	if compile {
		compiledProof = captureIdentityCompiledProof(t, ctx, *runtime, policy, read)
	}
	verifyCertificate := captureIdentityCertificate(t, ctx, runtime, user, peer, session, policy)
	verifyLifecycle := prepareIdentityLifecycleReadback(t, ctx, user, peer, session, cfg.Node.ID, compile)
	originalKey := (*runtime).Identity.Public
	originalStatus, err := (*runtime).workload.Status(ctx, taskKey)
	if err != nil || !originalStatus.Ready {
		t.Fatal("original container", err)
	}
	originalTask, err := (*runtime).workload.View(taskKey)
	originalSpec, specErr := workload.DecodeContainer(originalTask.State.Applied.Spec)
	if err != nil || specErr != nil || originalSpec.Inputs == nil {
		t.Fatal("original Task and sealed inputs", err, specErr)
	}
	volumes, err := policy.Volumes(read().State)
	originalVolume, found := volumes.Native("tenant", "app", "data")
	if err != nil || !found || originalVolume.Verify() != nil {
		t.Fatal("original Volume", err)
	}
	profile := filepath.Join(root, "cli.yaml")
	call := func(extra []*os.File, args ...string) []byte {
		t.Helper()
		out, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), profile, args, extra)
		if err != nil {
			t.Fatal("identity resource CLI", args, err, string(diagnostic), string(out))
		}
		return out
	}
	members, err := policy.Members(read().State)
	entry, found := members.Entry(cfg.Node.ID)
	if err != nil || !found {
		t.Fatal("installed identity", err)
	}
	call(nil, "node", "rotate-identity", cfg.Node.ID, "--operation", "replace-installed", "--expected-revision", fmt.Sprint(entry.Revision), "--request-id", "replace-installed-request")
	wait("durable preparation and actual local selector switch", func() bool {
		select {
		case <-(*runtime).IdentityRestart():
			return true
		default:
			return false
		}
	})
	// Ownership is recorded before any new-key native producer can start. A
	// failed cleanup keeps original recovery pins instead of inventing Gone.
	installed, err := bootstrap.Read(cfg)
	if err != nil {
		t.Fatal(err)
	}
	newKey := installed.Root.Self.Key
	if newKey == originalKey || len(installed.Root.Keys) == 0 {
		t.Fatal("shared activation did not select a replacement identity")
	}
	manifest["IdentityOwners"] = []string{desired.Owner(policy.Cluster, originalKey), desired.Owner(policy.Cluster, newKey)}
	saveManifest()
	if err := (*runtime).Close(); err != nil {
		t.Fatal("close original runtime after committed identity selector", err)
	}
	*runtime = nil
	restored, err := Open(cfg)
	if err != nil {
		t.Fatal("open current identity and original native namespaces", err)
	}
	*runtime = restored
	if restored.Identity.Public != newKey || restored.Mesh.LocalKey() != mydcp.Identity(newKey) || restored.installation.record.Root.OriginalKey() != originalKey {
		t.Fatal("new Root/TLS/runtime identity after actual reopen")
	}
	// Registered after the fixture's cleanup: stop future-owner producers first
	// while their exact original Volume/Bridge adapters remain open.
	t.Cleanup(func() {
		r := *runtime
		if r == nil || r.workload == nil {
			return
		}
		clean, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for _, key := range r.workload.Keys() {
			row, err := r.workload.View(key)
			if err != nil {
				t.Error(err)
				continue
			}
			resource := row.State.Desired.Resource
			if !resource.Present {
				resource = row.State.Applied
			}
			if !resource.Present {
				continue
			}
			if err = r.workload.Desired(key, row.State.Desired.Revision+1, resource.Generation, nil, max(1, row.Capacity)); err == nil {
				err = r.workload.Step(clean, key)
			}
			if err != nil {
				t.Error("replacement original Task rollback", err)
			}
		}
	})
	if _, err := restored.ResumeInstallation(ctx); err != nil {
		t.Fatal("resume original installation after identity replacement", err)
	}
	oldSession := *session
	peer.Key = mydcp.Identity(newKey)
	user.Peers = []mydcp.Peer{*peer}
	*session, err = user.Login(ctx, *peer, "admin", admin)
	if err != nil {
		t.Fatal("new current issuer login", err)
	}
	wait("installed replacement progress", func() bool {
		d, err := policy.Members(read().State)
		row, found := d.IdentityRotation(cfg.Node.ID, "replace-installed")
		return err == nil && found && row.Phase == "Installed" && d.MemberKey(newKey) && !d.MemberKey(originalKey) && !d.ReplicationKey(originalKey)
	})
	if _, err := user.MemberPage(ctx, *peer, oldSession, ""); err == nil {
		t.Fatal("old issuer session remained current")
	}
	if _, admitted := restored.Mesh.Peer(mydcp.Identity(originalKey)); admitted {
		t.Fatal("historic node key became a current TLS fallback")
	}
	if !closureOnly {
		verifyCertificate()
		verifyLifecycle()
	} else {
		manifest["IdentityMaterialReadbackReused"] = "native22/native24: exact original certificate/source recovery, current wire and negative old/repeated request checks; product code unchanged"
		saveManifest()
	}
	oldOwner, found := restored.nativeOwner(originalKey)
	if !found {
		t.Fatal("original native owner namespace missing")
	}
	if restored.checkerSourceBudget == nil || oldOwner.checkerSourceBudget != restored.checkerSourceBudget {
		t.Fatal("identity replacement split the logical node cache budget")
	}
	if compiledProof != nil {
		compiledProof.verifyRetained(t, ctx, restored, oldOwner, policy, read)
		compiledProof.verifyOriginalRunAfterRotation(t, oldOwner, policy, wait)
	}
	resumed, err := oldOwner.workload.Status(ctx, taskKey)
	retained, retainedErr := oldOwner.workload.View(taskKey)
	if err != nil || retainedErr != nil || !resumed.Ready || resumed.NativeID != originalStatus.NativeID || resumed.StartedAt != originalStatus.StartedAt || retained.State.Applied != originalTask.State.Applied || retained.State.LastID != originalTask.State.LastID {
		t.Fatal("rotation changed original live Task or journal", err, retainedErr)
	}
	// An existing sealed projection must survive the TLS key switch even while
	// its remote provider is sealed. This is an original-source permit check,
	// rather than decrypting with or authenticating as the historic key.
	vault.API("PUT", "sys/seal", nil, nil, vault.Admin)
	store, err := oldOwner.appProjectionStore()
	ready, readyErr := false, err
	if err == nil {
		ready, readyErr = store.Ready(ctx, *originalSpec.Inputs)
	}
	if readyErr != nil || !ready {
		t.Fatal("original sealed input after new current login", readyErr)
	}
	vault.UnsealOriginal()
	// The fixture trusts the dual-signed installed transition before updating
	// its explicit CLI target pin. The CLI then obtains a new issuer session.
	raw, err := os.ReadFile(profile)
	if err != nil || strings.Count(string(raw), fmt.Sprintf("%x", originalKey)) != 1 {
		t.Fatal("exact original CLI target pin", err)
	}
	raw = []byte(strings.Replace(string(raw), fmt.Sprintf("%x", originalKey), fmt.Sprintf("%x", newKey), 1))
	if err := os.WriteFile(profile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	call(nil, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	attachIdentityLifecycleReadback(t, filepath.Join(root, "compose.yaml"), compile)
	args := []string{"compose", "up", "--tenant", "tenant", "-f", filepath.Join(root, "compose.yaml"), "--operation", "identity-rollout", "--no-input"}
	var descriptors []*os.File
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
		descriptors = append(descriptors, reader)
		args = append(args, "--group-password-fd", fmt.Sprintf("%s=%d", group, 3+i))
	}
	call(descriptors, args...)
	for _, descriptor := range descriptors {
		_ = descriptor.Close()
	}
	wait("new current-key deployment using original retained resources", func() bool {
		a, err := policy.Apps(read().State)
		e, ok := a.Execution("tenant", "app")
		s := stage()
		return err == nil && ok && e.ActiveOperation() == "identity-rollout" && e.Status() == "Succeeded" && s.Observation != nil && s.Observation.Healthy && s.Observation.Owner == newKey
	})
	newTask, err := restored.workload.View(taskKey)
	newSpec, specErr := workload.DecodeContainer(newTask.State.Applied.Spec)
	newStatus, statusErr := restored.workload.Status(ctx, taskKey)
	if err != nil || specErr != nil || statusErr != nil || !newStatus.Ready || newStatus.NativeID == originalStatus.NativeID || newSpec.Node != desired.Owner(policy.Cluster, newKey) || newSpec.BridgeOwner != originalSpec.Node || len(newSpec.ResourceKeys) == 0 || newSpec.Inputs == nil || newSpec.Inputs.Binding == originalSpec.Inputs.Binding {
		t.Fatal("new Task identity did not consume the exact original Bridge", err, specErr, statusErr)
	}
	if restored.checkerSources == nil {
		t.Fatal("replacement source cache missing")
	}
	// The actual new Task must contain the immutable original provider proof.
	a, _ := policy.Apps(read().State)
	scripts, err := policy.Lifecycles(read().State)
	registered, registeredOK := scripts.Script("tenant", "identity-original")
	if err != nil || !registeredOK || len(registered.Versions) != 1 || registered.Versions[0].Source.Owner != originalKey {
		t.Fatal("original source history changed", err)
	}
	fact, data, sourceErr := restored.checkerSources.SourceArtifact(ctx, registered.Versions[0].Source.Descriptor())
	clear(data)
	if sourceErr != nil || fact.Owner != newKey || fact.ContentDigest() != registered.Versions[0].Source.ContentDigest() {
		t.Fatal("new Task did not consume original source in current cache", sourceErr)
	}
	s := stage()
	binding, found := a.Binding(deployment.ObjectRef{Key: taskKey, Revision: s.Result.Revision, Generation: s.Result.Generation})
	if !found || binding.Needs().Use.NodeKey != newKey || len(binding.Pins()) != 1 || binding.Pins()[0].Consumer.Owner.Key != originalKey || len(binding.Grants()) != 1 {
		t.Fatal("new current binding lost original Volume owner or fresh Secret grant")
	}
	certificates, certErr := policy.Certificates(read().State)
	if certErr != nil {
		t.Fatal("certificate store", certErr)
	}
	certificate := storedByRequest(t, certificates, "identity-server-request")
	if certificate.Request == "" {
		t.Fatal("original trusted public Ingress certificate missing", certErr)
	}
	if !closureOnly {
		verifyManagedIngressServing(t, ctx, oldOwner, cfg, policy, read, wait, certificate.Chain)
	} else {
		manifest["IdentityHTTPServingReused"] = "native22/native24 actual old Ingress to new Task H1/H2/H3 with trusted public certificate; same unchanged consumers"
		saveManifest()
	}
	if compiledProof != nil {
		compiledProof.verifyCurrentTask(t, ctx, restored, oldOwner, binding, policy, read, wait)
		manifest["IdentityCompiledReuse"] = "closed original compiler job and collection; same-DB historical cache; current Task cache-only preparation and compiled-run; no native Unknown-during-rotation coverage"
		saveManifest()
	}
	currentVolumes, err := policy.Volumes(read().State)
	currentVolume, found := currentVolumes.Native("tenant", "app", "data")
	if err != nil || !found || volumeapi.NativeBindingDigest(currentVolume) != volumeapi.NativeBindingDigest(originalVolume) {
		t.Fatal("rotation/redeployment replaced original NativeReady", err)
	}
	disk, err := restored.docker.API.VolumeInspect(ctx, originalVolume.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	marker, err := os.ReadFile(filepath.Join(disk.Volume.Mountpoint, "marker"))
	if err != nil || string(marker) != "volume-original" {
		t.Fatal("same physical Volume data after new deployment", err)
	}
	if !closureOnly {
		diagnosticFile := filepath.Join(root, "identity-diagnostics.tar.gz")
		call(nil, "node", "diagnostics", cfg.Node.ID, "--output", diagnosticFile)
		if info, err := os.Stat(diagnosticFile); err != nil || info.Mode().Perm() != 0600 || info.Size() == 0 || info.Size() > 64<<10 {
			t.Fatal("bounded private diagnostics download", err)
		}
		verifyManagedNodeDiagnostics(t, ctx, root, cfg.Node.ID, *user, *peer, *session, policy, read, diagnosticFile)
	} else {
		manifest["IdentityDiagnosticsReused"] = "request-rq12-native-current24: actual separate account CLI, output constraints and current revocation; unchanged diagnostics code"
		saveManifest()
	}
	var removal control.NodeRemovePlan
	if err := json.Unmarshal(call(nil, "node", "remove-plan", cfg.Node.ID), &removal); err != nil || removal.Removable || len(removal.Tasks) == 0 || len(removal.Volumes) == 0 {
		t.Fatal("CLI removal plan lost actual retained Task or Volume blockers", err)
	}
	call(nil, "compose", "down", "--tenant", "tenant", "-p", "app", "--operation", "identity-down")
	wait("actual old/new original reference settlement", func() bool {
		a, err := policy.Apps(read().State)
		i, found := a.Inventory("tenant", "app")
		_, retiring := i.Retirement()
		return err == nil && found && !retiring && len(a.Bindings().Live()) == 0
	})
	for _, owner := range restored.physicalOwners() {
		rows, err := owner.docker.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.mydc.owner="+owner.owner)})
		if err != nil || len(rows.Items) != 0 {
			t.Fatal("original native container remains after down", err)
		}
	}
	manifest["IdentityRotation"] = "actual CLI/dual-key preparation/Root/TLS reopen/current login/old session revocation/original sealed input/new Task with original Volume and Bridge/down"
	manifest["IdentityDiagnosticsVerifiedInThisRun"] = !closureOnly
	saveManifest()
}
