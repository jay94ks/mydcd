// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/tests/gitfixture"
	"github.com/jay94ks/seafield/tests/registryfixture"
	"github.com/jay94ks/seafield/tests/servicecallfixture"
	"github.com/jay94ks/seafield/tests/vaultfixture"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

// This boundary runs the real managed owner loop. The unsupported task remains
// pending; neither metadata acceptance nor this Bridge proves a running app.
func TestRealBoundaryManagedAppBridgeController(t *testing.T) {
	testRealManagedAppOwner(t, false, false, false, false)
}
func TestRealBoundaryManagedAppTaskVolumeController(t *testing.T) {
	testRealManagedAppOwner(t, true, true, false, false)
}
func TestRealBoundaryManagedAppTaskAuthorityWithoutMounts(t *testing.T) {
	testRealManagedAppOwner(t, true, false, false, false)
}
func TestRealBoundaryManagedAppVaultTaskClosure(t *testing.T) {
	testRealManagedAppOwner(t, true, true, true, false)
}
func TestRealBoundaryManagedAppAutomaticRetirement(t *testing.T) {
	testRealManagedAppOwner(t, true, true, true, true)
}
func testRealManagedAppOwner(t *testing.T, withWorkload, withVolume, withSecret, withRetirement bool, cli ...bool) {
	runManagedAppOwner(t, withWorkload, withVolume, withSecret, withRetirement, managedAppOrdinary, cli...)
}

type managedAppScenario uint8

const (
	managedAppOrdinary managedAppScenario = iota
	managedAppReplyLossN2
	managedAppReplyLossHandoff
	managedAppOrderedSecrets
	managedAppLocalSecrets
	managedAppNativeIdentityFaults
	managedAppTenantIsolation
	managedAppTenantRetirement
	managedAppSecondLifecycle
	managedAppVolumeDelete
	managedAppPrecreatedVolume
	managedAppBudgetedVolume
	managedAppBudgetedPrecreatedVolume
	managedAppDNS
	managedAppVolumeMove
	managedAppVolumeMoveAuto
	managedAppVolumeMoveReadonly
	managedAppVolumeMoveUnused
	managedAppVolumeMoveReverse
	managedAppVolumeMoveCancelResume
	managedAppVolumeMoveProcessCut
	managedAppDNSSecondLifecycle
	managedAppManagedNetwork
	managedAppFixedVolume
	managedAppChecker
	managedAppCompiledChecker
	managedAppRemoteCompiledChecker
	managedAppRegistry
	managedAppNodeIsolation
	managedAppCDVolumeMove
	managedAppE7DNSRetained
	managedAppContainerObserve
	managedAppNodeCLIPolicy
	managedAppLoggingPlain
	managedAppLoggingCD
	managedAppCDDecision
	managedAppContainerSessions
	managedAppExecRecovery
	managedAppCDLocalServices
	managedAppExternalRegistry
	managedAppIngressManagement
	managedAppServiceDiagnostics
	managedAppVolumeFiles
	managedAppStandalone
	managedAppStandaloneFixed
	managedAppStandaloneExtend
	managedAppStandaloneService
	managedAppStandaloneServiceRecreation
	managedAppStandaloneQuota
	managedAppPublishedPorts
	managedAppAllocatedPorts
	managedAppIdentityRotation
	managedAppIdentityCompiled
	managedAppIdentityClosure
	managedAppIngressOperations
)

func runManagedAppOwner(t *testing.T, withWorkload, withVolume, withSecret, withRetirement bool, scenario managedAppScenario, cli ...bool) {
	runManagedAppOwnerWithVolumeFileRead(t, withWorkload, withVolume, withSecret, withRetirement, scenario, nil, cli...)
}

// runManagedAppOwnerWithVolumeFileRead keeps public grant reads in the same
// accepted grant/revoke fixture; callers supply only their public-read observer.
func runManagedAppOwnerWithVolumeFileRead(t *testing.T, withWorkload, withVolume, withSecret, withRetirement bool, scenario managedAppScenario, grantRead volumeFileGrantReadHook, cli ...bool) {
	rq9Case := scenario == managedAppAllocatedPorts || scenario == managedAppPublishedPorts || scenario == managedAppVolumeFiles || scenario == managedAppStandalone || scenario == managedAppStandaloneFixed || scenario == managedAppStandaloneExtend || scenario == managedAppStandaloneService || scenario == managedAppStandaloneServiceRecreation || scenario == managedAppStandaloneQuota
	loggingCase := scenario == managedAppLoggingPlain || scenario == managedAppLoggingCD
	loggingCD := scenario == managedAppLoggingCD
	localCD := scenario == managedAppCDLocalServices
	diagnostics := scenario == managedAppServiceDiagnostics
	decisionCD := scenario == managedAppCDDecision || localCD || diagnostics
	sessionCase := scenario == managedAppContainerSessions || scenario == managedAppExecRecovery
	createReplyLoss := scenario == managedAppReplyLossN2 || scenario == managedAppReplyLossHandoff
	controlHandoff := scenario == managedAppReplyLossHandoff
	orderedSecrets := scenario == managedAppOrderedSecrets
	localSecrets := scenario == managedAppLocalSecrets
	withDNS := scenario == managedAppDNS || scenario == managedAppDNSSecondLifecycle || scenario == managedAppE7DNSRetained || scenario == managedAppStandalone
	cdMove := scenario == managedAppCDVolumeMove
	automaticMove := scenario == managedAppVolumeMoveAuto || scenario == managedAppVolumeMoveReadonly || scenario == managedAppVolumeMoveUnused || scenario == managedAppVolumeMoveReverse || scenario == managedAppVolumeMoveCancelResume || scenario == managedAppVolumeMoveProcessCut || cdMove
	volumeMove := scenario == managedAppVolumeMove || automaticMove
	externalAppCase := scenario == managedAppExternalRegistry
	withRegistry := scenario == managedAppRegistry
	identityCompiled := scenario == managedAppIdentityCompiled
	identityCase := scenario == managedAppIdentityRotation || scenario == managedAppIdentityClosure || identityCompiled
	remoteCheckers := scenario == managedAppRemoteCompiledChecker
	ingressManagement := scenario == managedAppIngressManagement
	compiledCheckers := scenario == managedAppCompiledChecker || remoteCheckers || identityCompiled
	// An app.yaml can no longer declare its own network (INVALID_FIELD):
	// every scenario borrows the managed shared-services network.
	managedNetwork := true
	withCheckers := scenario == managedAppChecker || compiledCheckers || scenario == managedAppNodeCLIPolicy
	withCLI := len(cli) > 0 && cli[0]
	withIngress := len(cli) > 2 && cli[2]
	withRemoteInputs := len(cli) > 3 && cli[3]
	if cdMove && (!withWorkload || !withVolume || !withSecret || !withRetirement || !withCLI || !withRemoteInputs) {
		t.Fatal("CD move requires the original CLI/remote Group/Volume/native fixture")
	}
	if withCheckers && (!withWorkload || !withVolume || !withSecret || !withRetirement || !withCLI) {
		t.Fatal("checker scenario requires the owned CLI/Task/Volume/Secret/retirement fixture")
	}
	if orderedSecrets && (!withWorkload || !withVolume || !withSecret || !withRetirement || !withCLI || !withRemoteInputs) {
		t.Fatal("ordered Secret scenario requires real CLI, remote Vault, Task/Volume and original retirement")
	}
	tag, cidr, manifest := os.Getenv("SFC_DOCKER_TEST_OWNER"), os.Getenv("SFC_DOCKER_TEST_CIDR"), os.Getenv("SFC_NATIVE_MANIFEST")
	if tag == "" || cidr == "" || manifest == "" || os.Geteuid() != 0 {
		t.Skip("requires prebuilt binary and owned native rollback baseline")
	}
	budget := 45 * time.Second
	if withWorkload {
		budget = 75 * time.Second
	}
	if withRetirement {
		budget = 110 * time.Second
	} // Includes 3 original Drain/Proof/Delete chains.
	if scenario == managedAppManagedNetwork || orderedSecrets {
		// RQ10 reads the original public state at multiple live/revoked/closed
		// boundaries, then consumes the exact closure or revokes both approvals.
		// This bounds the complete fixture, including its original retirement;
		// product RPC, native-effect and approval-age limits stay unchanged.
		budget = 3 * time.Minute
	}
	if scenario == managedAppTenantRetirement || scenario == managedAppSecondLifecycle || scenario == managedAppDNSSecondLifecycle || scenario == managedAppE7DNSRetained || scenario == managedAppVolumeMoveReverse || scenario == managedAppVolumeMoveProcessCut || scenario == managedAppCDVolumeMove || scenario == managedAppNodeIsolation || identityCase {
		budget = 270 * time.Second // two complete native lifecycles; a borrowed managed network adds retirement steps (about 220s measured)
	}
	if scenario == managedAppVolumeMoveAuto || scenario == managedAppVolumeMoveCancelResume || scenario == managedAppVolumeMoveReadonly || scenario == managedAppVolumeMoveUnused {
		// Source setup/retirement, the fixed 120s transfer or cancellation,
		// same-DB recovery, target/source reactivation AND final down all live
		// in this envelope. The transfer/per-call limits are not extended.
		budget = 5 * time.Minute
	}
	if scenario == managedAppVolumeMoveReverse || scenario == managedAppVolumeMoveProcessCut {
		// The same full move envelope plus a second lifecycle: the reverse
		// move, or the killed receiver's restart and resumed transfer.
		budget = 8 * time.Minute
	}
	if scenario == managedAppFixedVolume {
		budget = 240 * time.Second
	}
	if externalAppCase {
		// One finite app/reader lifecycle fits the original five-minute provider
		// credential; no build, Git or large-content opt-in shares this root.
		budget = 4 * time.Minute
	}
	if withRegistry {
		budget = 4 * time.Minute
		if os.Getenv("SFC_TEST_RQ6_REMAINING") == "prune-nonempty" {
			// This scope must observe the seed's real issued push token expire
			// before deletion. The ordinary fixture envelope is shorter than
			// that contractual lease. Preserve the token and per-call limits.
			budget += time.Duration(registry.MaxGrantSeconds) * time.Second
		}
		if os.Getenv("SFC_TEST_RQ6_IMAGE_BUILD") == "1" {
			// Existing registry/app recovery plus five finite 180s source
			// builds, their results and metadata cleanup. Product limits stay
			// fixed; no failed attempt caused an increase to this envelope.
			budget = 21 * time.Minute
			if os.Getenv("SFC_TEST_RQ6_LARGE_CONTEXT") == "1" {
				// Explicit 100MB transfer through thousands of separately
				// signed small operations, original replay and reclamation.
				budget += 8 * time.Minute
			}
		}
		if os.Getenv("SFC_TEST_RQ6_LARGE_REGISTRY") == "1" {
			// The explicit streaming push/read/GC runs independently of the
			// source build opt-in and retains the product's per-call limits.
			budget += 4 * time.Minute
		}
	}
	if decisionCD {
		// Initial app plus TWO explicit CD updates, source polling, and final
		// retirement. Match the existing CD logging fixture's whole envelope;
		// per-call/product budgets and CPU allocation remain unchanged.
		budget = 5 * time.Minute
	}
	if withCheckers {
		budget = 5 * time.Minute
	} // includes one finite offline build when selected
	if ingressManagement {
		// Shared preparation includes four app lifetimes, then eleven short
		// sequential checks and original retirement. This orchestration budget
		// includes that whole path; product/effect timeouts remain unchanged.
		budget = 10 * time.Minute
	}
	if loggingCase {
		budget = 5 * time.Minute
	} // rotation, exact retirement/recreation and optional source handoff/override
	if rq9Case || scenario == managedAppIngressOperations {
		budget = 5 * time.Minute // finite extra user paths, original managed rollback
	}
	if rq9Case && withCLI {
		// The CLI app setup also waits past the 30s unlinked observation
		// window to see the linked owner keep it live, and the shell case
		// retires six standalones and recovers the daemon (about 8 min measured
		// in the cloud before the final retirement).
		budget += 5 * time.Minute
	}
	if scenario == managedAppStandaloneFixed {
		budget = 8 * time.Minute // fixed no/always/on-failure, same DB, three native controls and both original retirements
	}
	if scenario == managedAppStandaloneServiceRecreation {
		// One original app plus standalone create, definition replacement,
		// explicit log recreation, same-DB recovery and both retirements.
		// This bounds the complete orchestration, not any product effect/RPC.
		budget = 8 * time.Minute
	}
	if sessionCase {
		budget = 5 * time.Minute // finite exec/stream scenarios on one original app
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	root := t.TempDir()
	if withIngress || withRemoteInputs || scenario == managedAppFixedVolume || withCheckers || withRegistry || loggingCase || sessionCase || decisionCD || externalAppCase || rq9Case {
		var e error
		root, e = os.MkdirTemp("", "sfc-managed-ingress-")
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if t.Failed() {
				t.Log("preserved original ingress recovery root", root)
			} else {
				_ = os.RemoveAll(root)
			}
		})
	}
	adminKey, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(adminKey.Private)
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := socket.LocalAddr().String()
	_ = socket.Close()
	cfgPath := filepath.Join(root, "node.yaml")
	document := fmt.Sprintf("version: 1\nnode:\n id: node-a\n listen: %q\n state_dir: %q\n identity_dir: %q\nmodules:\n network: {enabled: true}\n workload: {enabled: false}\n ingress: {enabled: false}\n", address, filepath.Join(root, "state"), filepath.Join(root, "identity"))
	if withWorkload {
		document = strings.Replace(document, "workload: {enabled: false}", "workload: {enabled: true}", 1)
	}
	var privateRegistry *managedRegistryNative
	if withRegistry {
		document, privateRegistry = configureManagedRegistryNative(t, root, document)
	}
	var ingressYAML string
	if withIngress {
		document, ingressYAML = managedIngressFixture(t, root, document)
	}
	var loggingStopFault *managedCreateReplyFault
	var createFault *managedCreateReplyFault
	var stopFault *managedCreateReplyFault
	var targetReadFault *managedCreateReplyFault
	var sourceUsageGate *volumeUsageGate
	if scenario == managedAppVolumeMoveReverse || scenario == managedAppVolumeMoveAuto {
		gateRoot := root
		if scenario == managedAppVolumeMoveAuto {
			// The target already has its own engine-fault.sock. Keep the
			// source readback delay on a distinct SDK socket.
			gateRoot = filepath.Join(root, "source-sdk")
			if err := os.Mkdir(gateRoot, 0700); err != nil {
				t.Fatal(err)
			}
		}
		proxy, gate := openManagedVolumeUsageGate(t, gateRoot)
		sourceUsageGate = gate
		document = strings.Replace(document, "unix:///var/run/docker.sock", proxy.endpoint, 1)
	}
	if scenario == managedAppVolumeMoveCancelResume {
		stopFault = openManagedStopFault(t, root)
		document = strings.Replace(document, "unix:///var/run/docker.sock", stopFault.endpoint, 1)
	}
	if createReplyLoss {
		if !withWorkload || !withVolume || !withSecret || !withRetirement || !withCLI || !withRemoteInputs {
			t.Fatal("Create reply loss requires the real CLI/remote Secret/Volume/retirement fixture")
		}
		createFault = openManagedCreateReplyFault(t, root)
		document = strings.Replace(document, "unix:///var/run/docker.sock", createFault.endpoint, 1)
	}
	if scenario == managedAppLoggingPlain {
		loggingStopFault = openManagedStopFault(t, root)
		document = strings.Replace(document, "unix:///var/run/docker.sock", loggingStopFault.endpoint, 1)
	}
	var execFault *managedExecReplyFault
	if sessionCase {
		proxy := openManagedCreateReplyFault(t, root)
		execFault = &managedExecReplyFault{ids: map[string]bool{}}
		proxy.mu.Lock()
		proxy.exec = execFault
		proxy.mu.Unlock()
		document = strings.Replace(document, "unix:///var/run/docker.sock", proxy.endpoint, 1)
	}
	if err = os.WriteFile(cfgPath, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadTestNode(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if ingressManagement {
		configureManagedIngressGateways(t, &cfg)
	}
	if diagnostics {
		ca, err := servicecallfixture.CA()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "service-ca.pem")
		if err := os.WriteFile(path, ca, 0600); err != nil {
			t.Fatal(err)
		}
		cfg.ServiceCAs = []config.ServiceCA{{Tenant: "tenant", CAFile: path}}
	}
	var gitSource *gitfixture.Fixture
	var gitCommit string
	if cdMove || loggingCD || decisionCD {
		gitSource = gitfixture.Open(t)
		cfg.GitCredentials = []config.GitCredential{gitSource.Credential(root, "tenant", "git-read")}
		if diagnostics {
			// Reuse only the fixture's public CA/repository scope. A separate
			// installed profile has a deliberately wrong private token, so the
			// actual HTTPS source can distinguish auth denial from TLS failure.
			bad := cfg.GitCredentials[0]
			bad.Profile = "git-bad"
			bad.PasswordFile = filepath.Join(root, "wrong-git-token")
			if err := os.WriteFile(bad.PasswordFile, []byte("owned-wrong-fixture-token\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg.GitCredentials = append(cfg.GitCredentials, bad)
		}
	}
	if privateRegistry != nil && os.Getenv("SFC_TEST_RQ6_IMAGE_BUILD") == "1" {
		privateRegistry.buildGit = gitfixture.Open(t)
		cfg.GitCredentials = append(cfg.GitCredentials, privateRegistry.buildGit.Credential(root, "tenant", "build-git"))
	}
	var vault *vaultfixture.Vault
	if withSecret {
		vault = vaultfixture.Open(t)
		if !withRemoteInputs {
			var providerLifetime []time.Duration
			if withRegistry && os.Getenv("SFC_TEST_RQ6_IMAGE_BUILD") == "1" {
				// The finite build scenario includes genuine push-lease waits.
				// Its initial provider input must cover that same envelope;
				// ordinary app fixtures retain their five-minute credential.
				providerLifetime = []time.Duration{budget}
			}
			installManagedVault(t, &cfg, root, vault, providerLifetime...)
			if localSecrets {
				installManagedSecretFiles(t, &cfg, root)
			}
		}
	}
	initialized, err := Initialize(ctx, cfg, adminKey.Public, "init-managed-bridge")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	clusterID := initialized.Installation.Root.Cluster
	owner := engine.Owner(clusterID, runtime.Identity.Public)
	key := deployment.ResourceKey("bridge", "tenant", "app", "app/node-a")
	stageKey := key
	if managedNetwork {
		key = "control/network-sources/bridge/tenant/shared-services/node-a"
		stageKey = deployment.ResourceKey("network-ref", "tenant", "app", "app/node-a")
	}
	if createFault != nil {
		createFault.arm(owner, deployment.ResourceKey("task", "tenant", "app", "web"))
	}
	// Persist public ownership before a command can cause native creation.
	public := map[string]any{"Owner": owner, "Key": key, "CIDR": cidr, "Root": root, "Tag": tag, "Cluster": clusterID, "NodeKey": runtime.Identity.Public}
	if withRegistry && os.Getenv("SFC_TEST_RQ6_IMAGE_BUILD") == "1" {
		public["ProviderCredentialLifetimeSeconds"] = uint64(budget / time.Second)
	}
	if withCheckers {
		public["LifecycleChecker"] = true
		public["CompiledChecker"] = compiledCheckers
		public["RemoteChecker"] = remoteCheckers
		public["CompilerImage"] = os.Getenv("SFC_LIFECYCLE_COMPILER_IMAGE")
	}
	saveManifest := func() {
		t.Helper()
		raw, _ := json.Marshal(public)
		if e := os.WriteFile(manifest, raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	saveManifest()
	// Cleanup is independent of the test context and always stops the producer.
	t.Cleanup(func() {
		var cleanupView cluster.View
		if runtime != nil {
			cleanupView, _ = runtime.Engine().Read(context.Background(), false)
			if e := runtime.Close(); e != nil {
				t.Error(e)
			}
			runtime = nil
		}
		clean, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		c, e := engine.Open(clean, "unix:///var/run/docker.sock", owner)
		if e != nil {
			t.Error(e)
			return
		}
		defer c.Close()
		defer cleanupManagedCompilerImage(t, clean, c, public)
		manager, e := network.OpenManager(filepath.Join(cfg.Node.StateDir, "network", "journal.db"), c)
		if e != nil {
			t.Error(e)
			return
		}
		defer manager.Close()
		// Replacement identities own separate future Task journals. Their
		// producer cleanup runs before this original-owner cleanup. A failed
		// replacement stop cannot justify returning the original Bridge pins.
		if owners, ok := public["IdentityOwners"].([]string); ok {
			for _, replacement := range owners {
				if replacement == owner {
					continue
				}
				remaining, err := c.API.ContainerList(clean, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.sfc.owner="+replacement)})
				if err != nil || len(remaining.Items) != 0 {
					t.Error("replacement Task remains; preserving original native recovery pins", err)
					return
				}
			}
		}
		if withIngress {
			cleanupManagedIngress(t, clean, cfg, manager, cleanupView)
		}
		if withWorkload {
			cleanupManagedTaskVolumes(t, clean, c, cfg, manager, public)
			remaining, inspectErr := c.API.ContainerList(clean, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.sfc.owner="+owner)})
			if inspectErr != nil || len(remaining.Items) != 0 {
				// A failed Task cleanup is not terminal native evidence. Keep
				// its original Bridge pins instead of returning them underneath
				// the live/unknown container and stranding original recovery.
				t.Error("owned Task remains; retaining original Bridge pins", inspectErr)
				return
			}
		}
		nodeKey, known := public["NodeKey"].([32]byte)
		if !known || !cleanupManagedRouteNative(t, clean, cfg, owner, nodeKey, manager, true, false) {
			t.Error("original route/isolation rollback incomplete; retaining Bridge pins")
			return
		}
		if !containsBridgeKey(manager.Keys(), key) {
			return
		}
		record, e := manager.View(key)
		if e != nil {
			t.Error(e)
			return
		}
		var spec network.BridgeSpec
		resource := record.State.Desired.Resource
		if !resource.Present {
			resource = record.State.Applied
		}
		if !resource.Present || json.Unmarshal([]byte(resource.Spec), &spec) != nil {
			if !resource.Present && record.State.Pending == nil && len(record.Consumers) == 0 {
				if gone, e := c.Gone(clean, "bridge", key); e == nil && gone {
					return
				}
			}
			t.Error("cannot recover original native source")
			return
		}
		for consumer, pin := range record.Consumers {
			if e = manager.ReturnConsumer(key, consumer, pin.Generation); e != nil {
				t.Error(e)
			}
		}
		revision := record.State.Desired.Revision + 1
		if e = manager.Desired(key, revision, resource.Generation, nil, max(1, record.Capacity)); e == nil {
			// A managed network's Bridge can need more than one step to
			// retire (drain, then close). Step again while it is pending.
			for e = manager.Step(clean, key); errors.Is(e, reconcile.ErrPending); e = manager.Step(clean, key) {
				select {
				case <-clean.Done():
					view, _ := manager.View(key)
					e = fmt.Errorf("%w: pending %+v pins %+v consumers %d", e, view.State.Pending, view.Pins, len(view.Consumers))
				case <-time.After(50 * time.Millisecond):
					continue
				}
				break
			}
		}
		if e == nil {
			var gone bool
			gone, e = manager.Gone(clean, key, revision, resource.Generation, spec)
			if !gone && e == nil {
				e = fmt.Errorf("original Bridge not Gone")
			}
		}
		if e != nil {
			t.Error("fixture journal cleanup", e)
		}
		rows, listErr := c.API.NetworkList(clean, client.NetworkListOptions{Filters: client.Filters{}.Add("label", "org.sfc.owner="+owner)})
		if listErr != nil {
			t.Error(listErr)
			return
		}
		expected, idErr := c.Identity("bridge", key, resource)
		for _, row := range rows.Items {
			t.Error("owned Bridge required fallback")
			got, e := c.API.NetworkInspect(clean, row.ID, client.NetworkInspectOptions{})
			if e != nil || idErr != nil || !expected.Matches(got.Network.Name, got.Network.Labels) || len(got.Network.Containers) != 0 {
				t.Error("fallback ownership mismatch", e)
				continue
			}
			if _, e = c.API.NetworkRemove(clean, row.ID, client.NetworkRemoveOptions{}); e != nil {
				t.Error(e)
			}
		}
	})
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	peer := sfcp.Peer{ID: cfg.Node.ID, Endpoint: address, Policy: sfcp.Policy{Key: sfcp.Identity(runtime.Identity.Public), Respond: true, Read: true, Member: true}}
	proof, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(proof.Private)
	mesh, err := sfcp.NewTransport(proof, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	user := userauth.Client{Mesh: mesh, Self: proof, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	enrolled, err := user.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "enroll-bridge", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: adminKey.Public, Enabled: true}}}}, adminKey.Private)
	if err != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("enroll", err)
	}
	session, err := user.Login(ctx, peer, "admin", adminKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	var remoteProvider, handoffControl *Runtime
	var observationControls []*Runtime
	read := func() cluster.View {
		t.Helper()
		for {
			var v cluster.View
			e := error(raft.ErrNotLeader)
			// A native owner may be a follower after a real control handoff.
			// Read the current SDK leader's quorum view, never its local replica.
			candidates := append([]*Runtime{runtime, remoteProvider, handoffControl}, observationControls...)
			for _, candidate := range candidates {
				if candidate != nil && candidate.Engine().IsLeader() {
					v, e = candidate.Engine().Read(ctx, true)
					break
				}
			}
			if e == nil {
				return v
			}
			if !errors.Is(e, raft.ErrNotLeader) && !errors.Is(e, raft.ErrLeadershipLost) {
				t.Fatal(e)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	policy := runtime.controlPolicy
	change := func(id, action string, expected uint64, payload any) {
		t.Helper()
		raw, e := control.ChangeBytes(action, "admin", expected, payload)
		if e != nil {
			t.Fatal(e)
		}
		var ch control.Change
		_ = json.Unmarshal(raw, &ch)
		if !runtime.Engine().IsLeader() {
			// A reopened follower's local install/Running readback does not prove
			// its user relay is ready. Wait only on an authenticated read before
			// preparing the one immutable mutation; never retry that submission.
			for {
				_, e = user.Whoami(ctx, peer, session)
				if e == nil {
					break
				}
				var unavailable *userauth.Error
				if !errors.As(e, &unavailable) || unavailable.Code != "unavailable" && unavailable.Code != "not-leader" {
					t.Fatal("follower user read readiness", e)
				}
				select {
				case <-ctx.Done():
					t.Fatal("follower user read readiness", ctx.Err())
				case <-time.After(20 * time.Millisecond):
				}
			}
		}
		op, e := user.Prepare(ctx, peer, session, id, ch)
		if e != nil {
			t.Fatal(id, e)
		}
		reply, e := user.Operation(ctx, peer, op, false)
		if e != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal(id, reply.Code, reply.Result, e)
		}
	}
	change("tenant", "create-tenant", 0, control.TenantID{ID: "tenant"})
	catalog, _ := policy.Catalog(read().State)
	tenant, _ := catalog.Tenant("tenant")
	change("nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a"}))
	var registry *registryfixture.Fixture
	if withWorkload {
		backend := os.Getenv("SFC_DOCKER_TEST_BACKEND")
		if backend == "" {
			t.Fatal("user-prebuilt backend required")
		}
		imageConfig := container.Config{Cmd: []string{"/backend"}, User: "10001:10001", Labels: map[string]string{"org.sfc.test.owner": tag}}
		if withVolume {
			imageConfig.Volumes = map[string]struct{}{"/data": {}}
		}
		registry = registryfixture.OpenPrepared(t, backend, imageConfig)
		public["Image"] = registry.Reference
		saveManifest()
		catalog, _ = policy.Catalog(read().State)
		tenant, _ = catalog.Tenant("tenant")
		change("registry-trust", "set-trust", tenant.Revision, control.TrustChange{Tenant: "tenant", Add: []access.TrustRule{access.TrustRule{Registry: registry.Registry, Repository: "fixture"}}})
	}
	for i, scope := range []string{"", "tenant"} {
		capacity := workload.Resources{CPU: 1e9, Memory: 256 << 20}
		maxConsumers := 8
		if ingressManagement {
			// Base app(2), DNS(1), shop(7), internal(4) need fourteen
			// distinct node-a edges. Provision this fixture before any app,
			// retaining all product/node-vs-tenant admission checks.
			maxConsumers = 16
		}
		if withCheckers {
			capacity = workload.Resources{CPU: 2e9, Memory: 1 << 30}
		}
		if withRegistry && os.Getenv("SFC_TEST_RQ6_IMAGE_BUILD") == "1" {
			// Initial fixture reservation for a 512MiB builder plus registry;
			// this is not a policy change in response to a failed execution.
			capacity.Memory = 1 << 30
		}
		if rq9Case {
			maxConsumers = max(maxConsumers, 16)
		} // app plus bounded standalone quota fixture
		change(fmt.Sprintf("limit-%d", i), "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: "node-a", Capacity: capacity, Networks: 2, MaxConsumers: maxConsumers, PacketQueuePackets: 128, PacketQueueBytes: 256 << 10, MaxIngressInstances: 2, MaxIngressListeners: 4, MaxIngressRequests: 4, MaxIngressConnections: 16, IngressBufferBytes: 256 << 10})
	}
	if withRemoteInputs {
		dockerEndpoint := ""
		if scenario == managedAppVolumeMoveAuto {
			targetReadFault = openManagedNetworkReadFault(t, root)
			dockerEndpoint = targetReadFault.endpoint
		}
		var configure []func(*config.Node)
		if ingressManagement {
			configure = append(configure, func(c *config.Node) { configureManagedIngressGateways(t, c) })
		}
		remoteProvider = prepareRemoteInputProvider(t, ctx, root, runtime, user, peer, session, read, change, vault, automaticMove || remoteCheckers || ingressManagement, dockerEndpoint, configure...)
	}
	if withSecret {
		if withRemoteInputs {
			remotePeer, _ := runtime.Mesh.Peer(sfcp.Identity(remoteProvider.Identity.Public))
			privateMesh, e := sfcp.NewTransport(proof, clusterID, func(key sfcp.Identity) (sfcp.Peer, bool) {
				if key == remotePeer.Key {
					return remotePeer, true
				}
				return peer, key == peer.Key
			})
			if e != nil {
				t.Fatal(e)
			}
			defer privateMesh.Close()
			remoteUser := userauth.Client{Mesh: privateMesh, Self: proof, Cluster: clusterID, Peers: []sfcp.Peer{peer, remotePeer}}
			if orderedSecrets {
				prepareManagedAppSecretScenario(t, ctx, remoteProvider, remoteUser, remotePeer, session, policy, read, change, runtime, managedAppOrderedSecrets)
			} else {
				prepareManagedAppSecrets(t, ctx, remoteProvider, remoteUser, remotePeer, session, policy, read, change, runtime)
			}
		} else {
			prepareManagedAppSecretScenario(t, ctx, runtime, user, peer, session, policy, read, change, runtime, scenario)
		}
	}
	if createFault != nil {
		promoteManagedFaultProvider(t, ctx, runtime, remoteProvider, policy, read, change)
		if controlHandoff {
			handoffControl = prepareManagedHandoffControl(t, ctx, root, runtime, user, peer, session, policy, read, change)
		}
	}
	var budgetCheck func(bool)
	budgeted := scenario == managedAppBudgetedVolume || scenario == managedAppBudgetedPrecreatedVolume
	if budgeted {
		budgetCheck = prepareManagedVolumeBudget(t, ctx, root, user, peer, policy, read)
	}
	var precreatedCheck func()
	if scenario == managedAppPrecreatedVolume || scenario == managedAppBudgetedPrecreatedVolume {
		var capacity []uint64
		if budgeted {
			capacity = []uint64{appVolumeReservation}
		}
		precreatedCheck = prepareManagedPrecreatedVolume(t, ctx, &runtime, root, user, peer, policy, read, capacity...)
	}
	var fixed *fixedAppNativeFixture
	if scenario == managedAppFixedVolume {
		public["FixedVolume"] = true
		saveManifest()
		fixed = prepareFixedAppNative(t, ctx, runtime, root, policy, read, change)
		public["FixedNative"] = fixed.ready
		saveManifest()
	}
	if privateRegistry != nil {
		privateRegistry.prepare(t, ctx, &runtime, root, user, peer, policy, read, change, registry, public, saveManifest)
	}
	var externalApp *externalRegistryAppNative
	if externalAppCase {
		externalApp = prepareExternalRegistryAppNative(t, ctx, runtime, root, user, peer, session, policy, read, change, registry, public, saveManifest)
	}
	remainingRQ6 := os.Getenv("SFC_TEST_RQ6_REMAINING")
	if privateRegistry != nil && remainingRQ6 == "prune-follower" {
		handoffControl = prepareManagedHandoffControl(t, ctx, root, runtime, user, peer, session, policy, read, change)
		privateRegistry.verifyRegistryPruneFollowerNative(t, ctx, runtime, handoffControl, user, peer, policy, read, change)
		return
	}
	if privateRegistry != nil && (remainingRQ6 == "image-queries" || remainingRQ6 == "image-content" || remainingRQ6 == "cache-runtime" || remainingRQ6 == "transfer-gate" || remainingRQ6 == "cancel-runtime" || remainingRQ6 == "prune-nonempty" || remainingRQ6 == "large-context") || externalApp != nil && (remainingRQ6 == "image-queries" || remainingRQ6 == "external-maintenance") {
		// These finite remaining scopes finish inside prepare. Keep the same
		// owned cleanup without replaying the already accepted app lifecycle.
		return
	}
	prefix := netip.MustParsePrefix(cidr)
	compose := []byte("name: app\nx-sfc: {}\nservices:\n web:\n  image: docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "\n  cpus: 0.1\n  mem_limit: 16m\n  networks: {app: {ipv4_address: " + prefix.Addr().Next().Next().String() + "}}\n  x-sfc: {node: node-a}\nnetworks:\n app:\n  x-sfc: {mtu: 1280, pools: {node-a: {cidr: " + cidr + ", gateway: " + prefix.Addr().Next().String() + "}}}\n")
	if withWorkload {
		compose = []byte(strings.Replace(string(compose), "docker.io/library/php@sha256:"+strings.Repeat("a", 64), registry.Reference, 1))
		compose = []byte(strings.Replace(string(compose), "  x-sfc: {node: node-a}", "  environment: {SFC_VOLUME_FIXTURE: \"1\", SFC_READINESS_FIXTURE: \"1\"}\n  volumes: [data:/data]\n  healthcheck: {test: [CMD, /backend, --volume-probe], interval: 1s, timeout: 1s, retries: 2}\n  x-sfc: {node: node-a, ready: {http: /readyz, port: 8080}}", 1))
		compose = append(compose, []byte("volumes:\n data:\n  x-sfc: {node: node-a, uid: 10001, gid: 10001, mode: \"0750\"}\n")...)
		if volumeMove {
			compose = []byte(strings.Replace(string(compose), "SFC_VOLUME_FIXTURE: \"1\", ", "SFC_GRACEFUL_FIXTURE: \"1\", SFC_VOLUME_FIXTURE: \"1\", ", 1))
		}
		if scenario == managedAppVolumeMoveReverse || scenario == managedAppVolumeMoveAuto {
			compose = []byte(strings.Replace(string(compose), "SFC_VOLUME_FIXTURE: \"1\", ", "SFC_MOVE_FIXTURE: \"1\", SFC_VOLUME_FIXTURE: \"1\", ", 1))
		}
		if !withVolume {
			compose = []byte(strings.Replace(string(compose), "SFC_VOLUME_FIXTURE: \"1\", ", "", 1))
			compose = []byte(strings.Replace(string(compose), "  volumes: [data:/data]\n", "", 1))
			compose = []byte(strings.Replace(string(compose), "--volume-probe", "--probe", 1))
			compose = compose[:strings.Index(string(compose), "\nvolumes:")+1]
		}
	}
	if scenario == managedAppContainerObserve || loggingCase || sessionCase {
		compose = []byte(strings.Replace(string(compose), "SFC_READINESS_FIXTURE: \"1\"", "SFC_READINESS_FIXTURE: \"1\", SFC_OBSERVATION_FIXTURE: \"1\"", 1))
	}
	if sessionCase {
		// The original backend and a concurrent Go exec share the cgroup.
		// This fixture allocation is not a new product resource default.
		compose = []byte(strings.Replace(string(compose), "mem_limit: 16m", "mem_limit: 64m", 1))
	}
	if loggingCase {
		input, err := deployment.ParseCompose(compose)
		if err != nil {
			t.Fatal(err)
		}
		service := input.Services["web"]
		driver := "local"
		if loggingCD {
			driver = "json-file"
		}
		service.Logging = &workload.LogPolicy{Driver: driver, Options: map[string]string{"max-size": "16k", "max-file": "2", "compress": "false"}}
		input.Services["web"] = service
		compose, err = yaml.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	if budgeted {
		compose = []byte(strings.Replace(string(compose), "{node: node-a, uid:", fmt.Sprintf("{node: node-a, size: %d, uid:", appVolumeReservation), 1))
	}
	if withSecret {
		compose = []byte(strings.Replace(string(compose), "  volumes: [data:/data]", "  volumes: [data:/data]\n  secrets: [{source: password, target: /run/secrets/db-password, uid: '10001', gid: '10001', mode: '0400'}]", 1))
		compose = []byte(strings.Replace(string(compose), "SFC_VOLUME_FIXTURE: \"1\",", "SFC_VOLUME_FIXTURE: \"1\", SFC_PROJECTION_FILE: /run/secrets/db-password,", 1))
		compose = []byte(strings.Replace(string(compose), "--volume-probe", "--projection-probe", 1))
		compose = []byte(strings.Replace(string(compose), "{node: node-a, ready:", "{node: node-a, secrets: {from: [data]}, ready:", 1))
		compose = append(compose, []byte("secrets:\n password:\n  x-sfc: {key: DB_PASSWORD}\n")...)
	}
	if withIngress && identityCase {
		prepareIdentityCertificate(t, ctx, runtime, user, peer, session, change)
	} else if withIngress {
		prepareIngressCertificate(t, ctx, user, peer, session, change)
	}
	if withIngress {
		compose = []byte(strings.Replace(string(compose), "x-sfc: {}", ingressYAML, 1))
	}
	if scenario == managedAppTenantIsolation {
		compose = []byte(strings.Replace(string(compose), "SFC_READINESS_FIXTURE: \"1\"", "SFC_READINESS_FIXTURE: \"1\", SFC_TENANT_FIXTURE: tenant", 1))
	}
	if withDNS {
		compose = []byte(strings.Replace(string(compose), "SFC_READINESS_FIXTURE: \"1\"", "SFC_READINESS_FIXTURE: \"1\", SFC_DNS_FIXTURE: \"1\"", 1))
		compose = []byte(strings.Replace(string(compose), "x-sfc: {mtu: 1280, pools:", "x-sfc: {mtu: 1280, dns: {enabled: true, zone: app.sfc.test, ttl_seconds: 1, negative_ttl_seconds: 1, transports: [udp, tcp], limits: {cache_entries: 4, queries_inflight: 4, tcp_connections: 2, request_timeout_ms: 2000}}, pools:", 1))
	}
	var orderedAudit *managedSecretAudit
	var groups []string
	if withSecret {
		groups = []string{"tenant/group"}
	}
	if orderedSecrets {
		compose = managedOrderedSecretDocument(compose)
		orderedAudit = openManagedSecretAudit(t, vault, policy, read)
		groups = []string{"tenant/common", "tenant/group"}
	}
	var cliChecks []func()
	var managementInput []byte
	if managedNetwork {
		parsed, err := deployment.ParseCompose(compose)
		if err != nil {
			t.Fatal(err)
		}
		if withDNS || scenario == managedAppSecondLifecycle {
			declared := parsed.Networks["app"]
			declared.Sfc.TunnelAddresses = map[string]string{"node-a": "198.18.254.1/32"}
			parsed.Networks["app"] = declared
			legacy, err := yaml.Marshal(parsed)
			if err != nil {
				t.Fatal(err)
			}
			compose, managementInput = managedSampleNetworkInputs(t, legacy, map[string]string{"app": "shared-services"})
		} else {
			parsed.Networks = map[string]deployment.ComposeNetwork{"app": {External: true, Name: "shared-services"}}
			if fixed != nil {
				parsed.Volumes = map[string]deployment.ComposeVolume{"data": {External: true, Name: fixed.ready.Spec.Scope.ID}}
			}
			compose, err = yaml.Marshal(parsed)
			if err != nil {
				t.Fatal(err)
			}
			managementInput = []byte(fmt.Sprintf("schema: 1\ntenant: tenant\nchanges:\n - id: shared-services\n   action: create-tun-network\n   expected: 0\n   payload:\n    Tenant: tenant\n    Name: shared-services\n    Members:\n     - Node: node-a\n       Pools:\n        - {ID: pool, Prefix: %s, Gateway: %s, MTU: 1280}\n", cidr, prefix.Addr().Next()))
		}
	}
	if diagnostics {
		input, err := deployment.ParseApp(compose)
		if err != nil {
			t.Fatal(err)
		}
		service := input.Services["web"]
		if service.Environment == nil {
			service.Environment = deployment.Environment{}
		}
		service.Environment["SFC_SERVICE_CALL_FIXTURE"] = "1"
		input.Services["web"] = service
		compose, err = yaml.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	var publishedPorts *managedPublishedPorts
	if scenario == managedAppPublishedPorts {
		compose, publishedPorts = prepareManagedPublishedPortsDocument(t, compose)
	}
	var allocatedPorts *managedAllocatedPorts
	if scenario == managedAppAllocatedPorts {
		compose, allocatedPorts = prepareManagedAllocatedPortsDocument(t, compose)
	}
	if withCLI {
		if cdMove || loggingCD || decisionCD {
			input, err := deployment.ParseApp(compose)
			if err != nil {
				t.Fatal(err)
			}
			policy := nativeGitPolicy(gitSource.Repository())
			if localCD {
				policy.Sync.Prune = true
			}
			input.Sfc.Delivery = &policy
			compose, err = yaml.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if decisionCD {
				compose = nativeGitServiceRevision(t, compose, "1", &policy, "web")
			}
			gitCommit = gitSource.Commit(compose)
			public["CDSourceCommit"] = gitCommit
			saveManifest()
		}
		if withCheckers {
			builders := []*Runtime{}
			if remoteCheckers {
				prepareManagedRemoteCheckerOwner(t, ctx, remoteProvider, root, policy, read, change, public, saveManifest)
				builders = append(builders, remoteProvider)
			}
			compilerImage := ""
			if compiledCheckers {
				builder := runtime
				if len(builders) > 0 {
					builder = builders[0]
				}
				compilerImage = prepareManagedCompilerImage(t, ctx, builder, public, saveManifest)
			}
			compose = prepareManagedCheckerApp(t, ctx, runtime, root, compose, compiledCheckers, compilerImage, change, builders...)
			if remoteCheckers {
				compose, managementInput = prepareManagedRemoteCheckerApp(t, compose, managementInput, policy, read, change)
			}
		}
		var cliWaitBudget time.Duration
		if ingressManagement {
			// The shared RQ7 setup includes remote Vault inputs before the first
			// native Task. Give its read-only wait an explicit part of the existing
			// whole-fixture envelope, without extending any product effect.
			cliWaitBudget = 90 * time.Second
		}
		cliChecks = prepareManagedComposeCLI(t, ctx, root, user, peer, compose, managementInput, policy, read, len(cli) == 1, cliWaitBudget, groups...)
	} else {
		if len(managementInput) != 0 {
			applyManagementChangesDirect(t, ctx, "prepare-network", managementInput, policy, read, change)
		}
		planned, e := user.PlanApp(ctx, peer, session, "tenant", control.AppPlanRequest{Document: compose})
		if e != nil || planned.AppPlan == nil {
			t.Fatal("plan", e)
		}
		change("upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: "tenant", App: "app", Deployment: "app", ID: "artifact", Length: planned.AppPlan.Length, Digest: sha256.Sum256(planned.AppPlan.Data)})
		change("part", "put-app-part", 1, control.AppUploadPart{Tenant: "tenant", ID: "artifact", Data: planned.AppPlan.Data})
		change("begin", "begin-app", 0, control.AppBegin{Tenant: "tenant", App: "app", Deployment: "app", Upload: "artifact", Operation: "rollout"})
	}
	if scenario == managedAppNodeCLIPolicy {
		apps, err := policy.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		original, exists := apps.Execution("tenant", "app")
		if !exists {
			t.Fatal("no accepted app before policy transition")
		}
		change("disable-node-cli", "set-node-cli-policy", 0, control.NodeCLIChange{DisableNodeCLIOperation: true})
		view := read()
		catalog, err := policy.Catalog(view.State)
		if err != nil || !catalog.NodeCLI().DisableNodeCLIOperation {
			t.Fatal("shared security policy not enabled before owner/lifecycle verification", err)
		}
		apps, err = policy.Apps(view.State)
		current, exists := apps.Execution("tenant", "app")
		if err != nil || !exists || current.ActiveOperation() != original.ActiveOperation() || current.Blueprint().Digest() != original.Blueprint().Digest() {
			t.Fatal("policy transition replaced the original app/goal", err)
		}
		public["NodeCLIPolicyRevision"] = catalog.NodeCLI().Revision
		public["OriginalAppPreservedAcrossPolicy"] = true
		saveManifest()
	}
	if externalApp != nil && len(cliChecks) == 3 {
		first, last := cliChecks[0], cliChecks[2]
		cliChecks[0] = func() { first(); externalApp.checkRunning(t, ctx, runtime, policy, read) }
		cliChecks[2] = func() { last(); externalApp.checkRetired(t, ctx, runtime, policy, read, change) }
	}
	if privateRegistry != nil && len(cliChecks) == 3 {
		first := cliChecks[0]
		cliChecks[0] = func() { first(); privateRegistry.checkRunning(t, ctx, &runtime, policy, read, change) }
	}
	if withRemoteInputs && !withCheckers && len(cliChecks) == 3 {
		first := cliChecks[0]
		cliChecks[0] = func() {
			first()
			verifyRemoteInputBoundary(t, ctx, runtime, remoteProvider, user, policy, read, change)
		}
	}
	if orderedSecrets && len(cliChecks) == 3 {
		first, last := cliChecks[0], cliChecks[2]
		cliChecks[0] = func() {
			first()
			public["OrderedSecrets"] = verifyManagedOrderedSecrets(t, ctx, runtime, root, user, peer, session, policy, read, change, orderedAudit)
			saveManifest()
		}
		cliChecks[2] = func() {
			last()
			finishManagedOrderedSecrets(t, ctx, root, policy, read, change, orderedAudit)
		}
	}
	if localSecrets && len(cliChecks) == 3 {
		first := cliChecks[0]
		cliChecks[0] = func() {
			first()
			public["InstalledFiles"] = verifyManagedSecretFiles(t, ctx, runtime, cfg, policy, read, change)
			saveManifest()
		}
	}
	if scenario == managedAppNativeIdentityFaults && len(cliChecks) == 3 {
		first := cliChecks[0]
		cliChecks[0] = func() {
			first()
			public["NativeIdentityFaults"] = verifyManagedNativeIdentityFaults(t, ctx, runtime, policy, read)
			saveManifest()
		}
	}
	if scenario == managedAppTenantRetirement && len(cliChecks) == 3 {
		first := cliChecks[0]
		cliChecks[0] = func() {
			first()
			public["TenantRetirement"] = verifyManagedTenantRetirement(t, ctx, runtime, root, user, peer, session, policy, read, change)
			saveManifest()
		}
	}
	if scenario == managedAppTenantIsolation && len(cliChecks) == 3 {
		first := cliChecks[0]
		cliChecks[0] = func() {
			first()
			public["TenantIsolation"] = verifyManagedTenantIsolation(t, ctx, runtime, root, cfg, user, peer, session, policy, read, change, registry.Reference)
			saveManifest()
		}
	}
	if (scenario == managedAppDNS || scenario == managedAppManagedNetwork || scenario == managedAppChecker || scenario == managedAppCompiledChecker) && len(cliChecks) == 3 {
		first, last := cliChecks[0], cliChecks[2]
		cliChecks[0] = func() {
			first()
			verifyNativePublicAppReads(t, ctx, runtime, root, user, peer, session, policy, read, change, compose, true)
		}
		cliChecks[2] = func() {
			last()
			verifyNativePublicAppReads(t, ctx, runtime, root, user, peer, session, policy, read, change, compose, false)
		}
	}
	stage := func() deployment.StageRecord {
		t.Helper()
		a, e := policy.Apps(read().State)
		if e != nil {
			t.Fatal(e)
		}
		execution, ok := a.Execution("tenant", "app")
		if !ok {
			t.Fatal("missing app")
		}
		s, _ := execution.Stage(stageKey)
		return s
	}
	wait := func(label string, f func() bool) {
		t.Helper()
		for !f() {
			if withDNS {
				runtime.mu.RLock()
				cause := runtime.moduleError
				runtime.mu.RUnlock()
				if cause != nil && strings.Contains(cause.Error(), "FEATURE_UNAVAILABLE") {
					t.Fatal(label, "declared DNS capability rejected its consumer", cause)
				}
			}
			select {
			case <-ctx.Done():
				runtime.mu.RLock()
				e := runtime.moduleError
				runtime.mu.RUnlock()
				t.Fatal(label, ctx.Err(), e)
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	wait("automatic managed Bridge/owner observation", func() bool {
		s := stage()
		return s.Result != nil && s.Result.Code == state.Applied && s.Observation != nil && s.Observation.Applied
	})
	if ingressManagement {
		// Capture the existing owner's first-failure state before the normal
		// cleanup closes it. Do not open a diagnostic CLI/wallet or resubmit
		// the original app when its health wait is unknown.
		t.Cleanup(func() {
			if !t.Failed() {
				return
			}
			diagnostic, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			for _, owner := range []*Runtime{runtime, remoteProvider} {
				if owner == nil {
					continue
				}
				engine := owner.Engine()
				owner.mu.RLock()
				moduleError, reportError := owner.moduleError, owner.reportError
				owner.mu.RUnlock()
				t.Log("RQ7 original owner failure", engine.ObservedNodeID(), "module", moduleError, "report", reportError)
				view, err := engine.Read(diagnostic, false)
				if err != nil {
					t.Log("RQ7 original owner state unavailable", err)
					continue
				}
				for _, key := range []string{"control/network-sources/bridge/tenant/shared-services/node-a", deployment.ResourceKey("task", "tenant", "app", "web")} {
					raw, err := owner.readModule(diagnostic, "observe", key, nil, view)
					var observation ModuleObservation
					if err != nil || json.Unmarshal(raw, &observation) != nil {
						t.Log("RQ7 original source observation unavailable", key, err)
						continue
					}
					t.Log("RQ7 original source", key, "native", observation.NativeID, "ready", observation.Ready, "error", observation.Error, "journal", observation.Journal, "module", observation.ModuleError, "report", observation.ReportError)
				}
			}
		})
		cliChecks[0]()
		verifyManagedIngressManagement(t, ctx, runtime, remoteProvider, cfg, root, user, peer, session, policy, read, change, wait, registry.Reference, public, saveManifest, func(current *testing.T) { t = current })
		cliChecks[1]()
		cliChecks[2]()
		return
	}
	if withWorkload {
		if createFault != nil {
			public["CreateReplyFault"] = verifyManagedCreateReplyFault(t, ctx, createFault, &runtime, &remoteProvider, handoffControl, cfg, user, peer, session, policy, read, change, wait)
			saveManifest()
		}
		if volumeMove {
			reject := func(id, action string, expected uint64, payload any, want state.Code) {
				t.Helper()
				raw, err := control.ChangeBytes(action, "admin", expected, payload)
				if err != nil {
					t.Fatal(err)
				}
				var ch control.Change
				_ = json.Unmarshal(raw, &ch)
				op, err := user.Prepare(ctx, peer, session, id, ch)
				if err != nil {
					t.Fatal("prepare rejection case", id, action, err)
				}
				reply, err := user.Operation(ctx, peer, op, false)
				if err != nil || reply.Result == nil || reply.Result.Code != want {
					t.Fatal(id, reply.Result, err)
				}
				if action == "create-tun-network" && reply.Result.Revision != op.RootRevision {
					t.Fatal("network rejection used a stale root rather than the declared overlap", id, op.RootRevision, reply.Result)
				}
			}
			moveApprover := remoteProvider.Identity.Public
			approveMove := func(origin control.UserOperation) {
				t.Helper()
				remotePeer, ok := runtime.Mesh.Peer(sfcp.Identity(moveApprover))
				if !ok {
					t.Fatal("move approver member")
				}
				privateMesh, err := sfcp.NewTransport(proof, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) {
					if k == remotePeer.Key {
						return remotePeer, true
					}
					return peer, k == peer.Key
				})
				if err != nil {
					t.Fatal(err)
				}
				defer privateMesh.Close()
				requester := userauth.Client{Mesh: privateMesh, Self: proof, Cluster: clusterID, Peers: []sfcp.Peer{peer, remotePeer}}
				query := control.VaultApprovalPlanRequest{Realm: "tenant", ID: "move-target-groups", Origin: &origin}
				forged := origin
				forged.RequestID = "unaccepted-move"
				forged.Signature = ed25519.Sign(proof.Private, control.OperationBytes(forged))
				bad := query
				bad.Origin = &forged
				if _, err = requester.PlanVaultApprovals(ctx, peer, session, "tenant", bad); err == nil {
					t.Fatal("different accepted move authorized Group plan")
				}
				plan, err := requester.PlanVaultApprovals(ctx, peer, session, "tenant", query)
				if err != nil || len(plan.Targets) != 1 {
					t.Fatal("original target Group plan", err)
				}
				want := plan.Targets[0]
				if want.Existing != nil || want.Approver == nil || len(want.Target.Nodes) != 1 || want.Target.Nodes[0].Key != moveApprover {
					t.Fatal("source approval covered target or target scope changed")
				}
				request := userauth.SecretRequest{Realm: want.Target.Realm, ID: want.Target.ApprovalID, Mode: "approve", Target: &want.Target, Origin: &origin, Password: []byte("wrong-fixture-password")}
				reply, err := requester.WriteVault(ctx, remotePeer, session, request)
				if err == nil || reply.VaultApproval != nil {
					t.Fatal("wrong Group password accepted")
				}
				request.Password = []byte("private-native-group-password")
				reply, err = requester.WriteVault(ctx, remotePeer, session, request)
				clear(request.Password)
				if err != nil || reply.VaultApproval == nil {
					t.Fatal("actual target Group approval", err)
				}
				reused, err := requester.PlanVaultApprovals(ctx, peer, session, "tenant", query)
				if err != nil || len(reused.Targets) != 1 || reused.Targets[0].Existing == nil {
					t.Fatal("original target approval not reusable", err)
				}
			}
			reopenSource := func(whenClosed func()) *Runtime {
				t.Helper()
				if err := runtime.Engine().Snapshot(ctx); err != nil {
					t.Fatal(err)
				}
				if err := runtime.Close(); err != nil {
					t.Fatal(err)
				}
				runtime = nil
				if whenClosed != nil {
					whenClosed()
				}
				runtime, err = Open(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := runtime.InstallConfiguration(ctx); err != nil {
					t.Fatal(err)
				}
				return runtime
			}
			reopenTarget := func(whenClosed func()) *Runtime {
				t.Helper()
				providerConfig := remoteProvider.installation.config
				if err := remoteProvider.Engine().Snapshot(ctx); err != nil {
					t.Fatal(err)
				}
				if err := remoteProvider.Close(); err != nil {
					t.Fatal(err)
				}
				remoteProvider = nil
				if whenClosed != nil {
					whenClosed()
				}
				remoteProvider, err = Open(providerConfig)
				if err != nil {
					t.Fatal(err)
				}
				// Runs before the existing native rollback, including a failed
				// install. The original factory cleanup owns only the old Runtime.
				reopened := remoteProvider
				t.Cleanup(func() {
					if err := reopened.Close(); err != nil {
						t.Error(err)
					}
				})
				if _, err := remoteProvider.InstallConfiguration(ctx); err != nil {
					t.Fatal(err)
				}
				return remoteProvider
			}
			controls := managedMoveNativeControls{sourceStop: stopFault, targetNetwork: targetReadFault, sourceUsage: sourceUsageGate, reopenSource: reopenSource, reopenTarget: reopenTarget, sourceRuntime: func() *Runtime { return runtime }, cdSource: gitSource}
			if cdMove {
				wait("actual registered Group/Volume Git candidate", func() bool {
					apps, err := policy.Apps(read().State)
					d, found := apps.Delivery("tenant", "app")
					candidate, selected := d.CandidateSelection()
					return err == nil && found && selected && candidate.Commit == gitCommit && d.SourceError() == ""
				})
			}
			verifyManagedAppMoveQuiesce(t, ctx, runtime, remoteProvider, root, compose, policy, read, change, reject, approveMove, wait, scenario, controls)
			if cdMove {
				public["CDGroupVolumeMoveSource"] = gitSource.Stats()
				saveManifest()
			}
			return
		}
		if fixed != nil {
			verifyFixedAppNative(t, ctx, &runtime, cfg, policy, read, wait, fixed, cliChecks)
		} else {
			if scenario == managedAppNodeIsolation {
				verifyManagedNodeResourceIsolation(t, ctx, &runtime, cfg, root, compose, policy, read, change, wait, key, cliChecks, func() *Runtime {
					handoffControl = prepareManagedHandoffControl(t, ctx, root, runtime, user, peer, session, policy, read, change)
					return handoffControl
				})
				public["NodeResourceIsolation"] = "live app add/promote control; CLI isolate/restore and original request replay; second live app owner removal waits on actual app/network closure then SDK RemoveServer; retained bytes and original history; leader-removal handoff is separate coverage"
				saveManifest()
				return
			}
			if withCheckers {
				builders := []*Runtime{}
				if remoteCheckers {
					builders = append(builders, remoteProvider)
				}
				verifyManagedCheckerApp(t, ctx, runtime, policy, read, wait, compiledCheckers, !remoteCheckers && !identityCompiled, builders...)
				if !remoteCheckers {
					verifyManagedLifecyclePublicReads(t, ctx, root, user, peer, session, policy, read, true, false, false)
				}
				if remoteCheckers {
					verifyManagedRemoteCheckerResults(t, ctx, runtime, remoteProvider, wait)
				}
			}
			var recovered func(*Runtime)
			if publishedPorts != nil {
				first, last := cliChecks[0], cliChecks[2]
				var finish func(*Runtime)
				cliChecks[0] = func() {
					first()
					finish = prepareManagedPublishedPortsNative(t, ctx, runtime, root, compose, user, peer, session, policy, read, wait, publishedPorts)
				}
				recovered = func(next *Runtime) {
					if finish == nil {
						t.Fatal("published-port preparation missing before same-DB recovery")
					}
					finish(next)
				}
				cliChecks[2] = func() { last(); publishedPorts.assertClosed(t, ctx) }
			}
			if allocatedPorts != nil {
				first, last := cliChecks[0], cliChecks[2]
				var finish func(*Runtime)
				cliChecks[0] = func() {
					first()
					finish = prepareManagedAllocatedPortsNative(t, ctx, runtime, root, compose, user, peer, session, policy, read, wait, allocatedPorts)
				}
				recovered = func(next *Runtime) {
					if finish == nil {
						t.Fatal("allocated-port preparation missing before same-DB recovery")
					}
					finish(next)
				}
				cliChecks[2] = func() { last(); allocatedPorts.assertClosed(t, ctx) }
			}
			if scenario == managedAppIngressOperations {
				first := cliChecks[0]
				var finish func(*Runtime)
				cliChecks[0] = func() {
					first()
					finish = prepareIngressOperationsNative(t, ctx, runtime, root, user, peer, session, policy, read, change, wait)
				}
				recovered = func(next *Runtime) {
					if finish == nil {
						t.Fatal("ingress operation preparation missing before reopen")
					}
					finish(next)
				}
			}

			if scenario == managedAppVolumeFiles {
				last := cliChecks[2]
				cliChecks[2] = func() {
					last()
					verifyVolumeFilesUserNative(t, ctx, &runtime, cfg, root, user, peer, session, policy, read, change, wait, grantRead)
				}
			}
			if scenario == managedAppStandalone || scenario == managedAppStandaloneFixed || scenario == managedAppStandaloneExtend || scenario == managedAppStandaloneService || scenario == managedAppStandaloneServiceRecreation || scenario == managedAppStandaloneQuota {
				first := cliChecks[0]
				var finishStandalone func(*Runtime)
				cliChecks[0] = func() {
					first()
					if scenario == managedAppStandaloneService || scenario == managedAppStandaloneServiceRecreation {
						finishStandalone = prepareStandaloneServiceNative(t, ctx, runtime, root, compose, user, peer, session, policy, read, change, wait, scenario == managedAppStandaloneServiceRecreation)
					} else {
						finishStandalone = prepareStandaloneUserNative(t, ctx, runtime, root, user, peer, session, policy, read, change, wait, public, saveManifest, scenario == managedAppStandaloneQuota, scenario == managedAppStandaloneFixed || scenario == managedAppStandaloneExtend, scenario == managedAppStandaloneExtend)
					}
				}
				// The preparation hook runs inside verifyManagedTaskVolume,
				// before its existing same-DB Runtime.Close/Open boundary.
				recovered = func(next *Runtime) {
					if finishStandalone == nil {
						t.Fatal("standalone preparation did not run before same-DB recovery")
					}
					finishStandalone(next)
				}
			}
			var sessionFinished func()
			if sessionCase {
				wait("initial session app ready", func() bool {
					a, err := policy.ReadApps(read().State)
					e, ok := a.Execution("tenant", "app")
					s, _ := e.Stage(deployment.ResourceKey("task", "tenant", "app", "web"))
					return err == nil && ok && e.Status() == "Succeeded" && s.Observation != nil && s.Observation.Healthy
				})
				cliChecks[0]()
				cliChecks[0] = func() {}
				allCases := scenario == managedAppContainerSessions
				recovered, sessionFinished, handoffControl = verifyManagedContainerSessions(t, ctx, runtime, root, user, peer, session, policy, read, change, execFault, allCases)
				public["ContainerSessions"] = "recovery: original native exec/disconnect/duplicate; remote owner; same DB recovery; daemon live I/O close; original watch stops on Task closure; exact final down/Volume retention"
				if allCases {
					public["ContainerSessions"] = "full: " + public["ContainerSessions"].(string) + "; Unix/QUIC argv/TTY/EOF/exit, follow/watch and explicit replacement, CLI/PTY, auth/expiry/revocation/backpressure, Attach reply loss"
				}
				saveManifest()
			}
			if scenario == managedAppContainerObserve {
				recovered = func(r *Runtime) {
					observationControls = verifyManagedContainerObservation(t, ctx, r, root, user, peer, session, policy, read, change)
				}
			}
			if privateRegistry != nil {
				recovered = func(r *Runtime) { privateRegistry.checkRecovered(t, ctx, r, policy, read) }
			}
			if externalApp != nil {
				recovered = func(r *Runtime) { externalApp.checkRecovered(t, ctx, r, policy, read) }
			}
			if loggingCase {
				// The bounded CLI wait smoke starts from a ready app. CD adds
				// a real source step before Task creation; consuming the CLI's
				// default wait budget on initial provisioning does not test
				// logger behavior or readiness of an already running app.
				wait("initial logging app ready before bounded CLI query", func() bool {
					a, err := policy.ReadApps(read().State)
					e, ok := a.Execution("tenant", "app")
					s, _ := e.Stage(deployment.ResourceKey("task", "tenant", "app", "web"))
					return err == nil && ok && e.Status() == "Succeeded" && s.Observation != nil && s.Observation.Healthy
				})
				cliChecks[0]() // Verify the original rollout before explicit recreation retires that operation.
				var remote *Runtime
				if loggingCD {
					handoffControl = prepareManagedHandoffControl(t, ctx, root, runtime, user, peer, session, policy, read, change)
					remote = handoffControl
				}
				latest := verifyManagedContainerLogging(t, ctx, &runtime, cfg, root, user, peer, session, policy, read, wait, loggingStopFault, remote, loggingCD)
				cliChecks[0] = func() {
					output, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), []string{"compose", "wait", "-p", "app", "--tenant", "tenant", "--operation", latest}, nil)
					if err != nil {
						t.Fatal("current post-clear rollout health", err, string(diagnostic), string(output))
					}
				}
			}
			if identityCase {
				verifyManagedIdentityResources(t, ctx, &runtime, cfg, root, &user, &peer, &session, adminKey.Private, policy, read, wait, vault, public, saveManifest, groups, identityCompiled, scenario == managedAppIdentityClosure)
				return
			}
			if decisionCD {
				wait("initial actual app for CD decision", func() bool {
					a, err := policy.ReadApps(read().State)
					e, ok := a.Execution("tenant", "app")
					stage, _ := e.Stage(deployment.ResourceKey("task", "tenant", "app", "web"))
					return err == nil && ok && e.Status() == "Succeeded" && stage.Observation != nil && stage.Observation.Healthy
				})
				cliChecks[0]()
				if diagnostics {
					handoffControl = verifyManagedServiceDiagnostics(t, ctx, runtime, cfg, root, user, peer, session, policy, read, wait, change, gitSource, compose, gitCommit)
					originalRetired := cliChecks[2]
					cliChecks[2] = func() {
						originalRetired()
						verifyManagedServiceUnavailableAfterDown(t, ctx, user, peer, session)
					}
				} else if localCD {
					verifyManagedCDLocalServices(t, ctx, &runtime, cfg, root, user, peer, session, policy, read, wait, gitSource, compose, gitCommit)
				} else {
					observationControls = verifyManagedCDDecisions(t, ctx, runtime, root, user, peer, session, policy, read, change, wait, gitSource, compose, gitCommit)
				}
				t.Log("CD scenario complete; starting original app retirement")
				cliChecks[1]()
				lastRetirement := ""
				unchangedSince := time.Now()
				wait("original CD app retirement", func() bool {
					apps, err := policy.ReadApps(read().State)
					if err != nil {
						t.Fatal(err)
					}
					inventory, ok := apps.Inventory("tenant", "app")
					if !ok {
						t.Fatal("original CD inventory missing")
					}
					retirement, pending := inventory.Retirement()
					if !pending {
						return true
					}
					graph := cdNativeRetirementGraph(inventory, retirement)
					raw, _ := json.Marshal(graph)
					if string(raw) != lastRetirement {
						lastRetirement = string(raw)
						unchangedSince = time.Now()
						public["CDRetirementGraph"] = graph
						saveManifest()
						t.Log("original CD retirement graph", lastRetirement)
					}
					if path := os.Getenv("SFC_NATIVE_STACKS"); filepath.IsAbs(path) && time.Since(unchangedSince) >= 10*time.Second {
						file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
						if err != nil {
							t.Fatal("original stall stack output", err)
						}
						err = pprof.Lookup("goroutine").WriteTo(file, 2)
						_ = file.Close()
						if err != nil {
							t.Fatal(err)
						}
						t.Fatal("diagnostic cut after original retirement stalled; original DB/graph and goroutines preserved")
					}
					return false
				})
				cliChecks[2]()
				if gone, err := runtime.docker.Gone(ctx, "container", deployment.ResourceKey("task", "tenant", "app", "web")); err != nil || !gone {
					t.Fatal("CD app did not close original native resources", err)
				}
			} else {
				verifyManagedTaskVolume(t, ctx, &runtime, cfg, policy, read, change, wait, recovered, registry.Reference, withVolume, vault, withRetirement, cliChecks...)
			}
			if sessionFinished != nil {
				sessionFinished()
			}
			if privateRegistry != nil {
				privateRegistry.finish(t, ctx, &runtime, policy, read, change)
			}
			if withCheckers {
				peers := []*Runtime{}
				if remoteCheckers {
					peers = append(peers, remoteProvider)
				}
				var publicReads func(bool, bool)
				if !remoteCheckers {
					publicReads = func(retired, deleted bool) {
						verifyManagedLifecyclePublicReads(t, ctx, root, user, peer, session, policy, read, false, retired, deleted)
					}
				}
				verifyManagedCheckerRetirement(t, runtime, policy, read, change, wait, publicReads, peers...)
			}
		}
		if managedNetwork {
			source := read().State.Object(key)
			if !source.Present {
				t.Fatal("app down deleted the management source")
			}
			if _, err := runtime.network.Inspect(ctx, key); err != nil {
				t.Fatal("app down deleted the management native bridge", err)
			}
			// Without retirement the app is never taken down, so its borrow
			// stays until the fixture cleanup returns it.
			row, err := runtime.network.View(key)
			if err != nil || withRetirement && len(row.Consumers) != 0 || !row.State.Desired.Present || !row.State.Applied.Present || row.State.Pending != nil {
				t.Fatal("app borrow was not fully returned while preserving management native", err, len(row.Consumers), row.State.Pending)
			}
			t.Log("P0 actual manage apply changes -> managed source -> app-only reference -> Secret/Volume/Task/Ingress -> same DB -> app down/borrow return; management source/native preserved until separate fixture rollback")
			if scenario == managedAppManagedNetwork {
				verifyManagedNetworkClosureObservation(t, ctx, runtime, policy, read, change, wait, key, user, peer, session, root)
			}
		}
		if scenario == managedAppPrecreatedVolume || scenario == managedAppBudgetedPrecreatedVolume {
			precreatedCheck()
			if budgeted {
				budgetCheck(false)
			}
			verifyManagedAppVolumeDelete(t, ctx, runtime, root, policy, read, wait)
			if budgeted {
				budgetCheck(true)
			}
		}
		if scenario == managedAppBudgetedVolume {
			budgetCheck(false)
			verifyManagedAppVolumeDelete(t, ctx, runtime, root, policy, read, wait)
			budgetCheck(true)
		}
		if scenario == managedAppVolumeDelete {
			verifyManagedAppVolumeDelete(t, ctx, runtime, root, policy, read, wait)
		}
		if scenario == managedAppSecondLifecycle || scenario == managedAppDNSSecondLifecycle || scenario == managedAppE7DNSRetained {
			verifySecondAppLifecycle(t, ctx, runtime, root, compose, policy, read, change, vault, scenario == managedAppE7DNSRetained)
		}
		if createFault != nil {
			evidence := createFault.snapshot()
			if evidence.Creates != 1 || evidence.Starts != 1 {
				t.Fatal("original native request count changed", evidence)
			}
			public["CreateReplyFinal"] = evidence
			saveManifest()
		}
		return
	}
	original := stage()
	source := read().State.Object(key)
	native, err := runtime.network.Inspect(ctx, key)
	observed := native
	if managedNetwork && original.Observation != nil && strings.HasPrefix(original.Observation.Native, "borrow/"+native+"/") {
		// An app borrows the managed Bridge: its observation names the
		// borrowed native network and its own consumer.
		observed = original.Observation.Native
	}
	if err != nil || original.Observation == nil || observed != original.Observation.Native || !ed25519.Verify(runtime.Identity.Public[:], deployment.ObservationBytes(*original.Observation), original.Observation.Signature) {
		t.Fatalf("actual signed native observation: %v native %q stage %+v", err, native, original.Observation)
	}
	projection, err := policy.ProjectResources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	var spec network.BridgeSpec
	if managedNetwork {
		spec = *projection.ManagedSources[key].Bridge
	} else {
		spec = *projection.Goals[key].Bridge
	}
	specRaw, _ := json.Marshal(spec)
	physical, err := runtime.docker.Identity("bridge", key, reconcile.Resource{Present: true, Generation: source.Generation, Spec: string(specRaw)})
	if err != nil {
		t.Fatal(err)
	}
	public["Name"], public["Labels"], public["Spec"], public["Generation"], public["NativeID"] = physical.Name, physical.Labels, json.RawMessage(specRaw), source.Generation, native
	saveManifest()
	first, err := runtime.network.Acquire(ctx, key, "first", source.Generation)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runtime.network.Acquire(ctx, key, "second", source.Generation)
	if err != nil {
		t.Fatal(err)
	}
	// A managed Bridge also holds the app's own borrow.
	held, err := runtime.network.View(key)
	if err != nil || len(held.Consumers) < 2 {
		t.Fatal("acquired consumers", err, len(held.Consumers))
	}
	quotas, _ := policy.Resources(read().State)
	limit, _ := quotas.Quotas.Limit("", "node-a")
	revision := limit.Revision
	limit.Revision = 0
	limit.MaxConsumers = 1
	change("shrink", "set-node-quota", revision, limit)
	wait("runtime shared consumer resize", func() bool {
		r, e := runtime.network.View(key)
		return e == nil && r.Capacity == 1 && len(r.Consumers) == len(held.Consumers)
	})
	if _, err = runtime.network.Acquire(ctx, key, "third", source.Generation); err == nil {
		t.Fatal("consumer shrink lost admission limit")
	}
	nodeMesh, err := sfcp.NewTransport(runtime.Identity, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer nodeMesh.Close()
	request, _ := json.Marshal(control.NativeRequest{Source: deployment.ObjectRef{Key: key, Generation: source.Generation, Revision: source.Revision}})
	call := func(m *sfcp.Transport, self *identity.Identity, method string, input []byte) (cluster.ManagementReply, error) {
		return cluster.CallManagement(ctx, m, self, clusterID, peer, cluster.ManagementRequest{Method: method, Latest: true, Input: input})
	}
	permitReply, err := call(nodeMesh, runtime.Identity, "app-native-permit", request)
	var permit control.NativePermit
	_ = json.Unmarshal(permitReply.Data, &permit)
	if err != nil || permitReply.Code != "ok" || permit.MaxConsumers != 1 {
		t.Fatal("real member permit", permitReply.Code, err)
	}
	foreign, foreignErr := call(mesh, proof, "app-native-permit", request)
	if foreignErr == nil && foreign.Code == "ok" {
		t.Fatal("user transport obtained member permit")
	}
	originalRaw, _ := state.EncodeCommand(*original.Command)
	resultReply, err := call(nodeMesh, runtime.Identity, "app-result", originalRaw)
	var found control.AppResult
	_ = json.Unmarshal(resultReply.Data, &found)
	if err != nil || resultReply.Code != "ok" || !found.Found || found.Result == nil || *found.Result != *original.Result {
		t.Fatal("real original result", resultReply.Code, err)
	}
	if err = runtime.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime = nil
	runtime, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	restored, err := runtime.network.InspectConsumer(ctx, key, "first", source.Generation)
	restoredSecond, err2 := runtime.network.InspectConsumer(ctx, key, "second", source.Generation)
	if err != nil || err2 != nil || restored.NetworkID != native || restored.Pin != first.Pin || restoredSecond.Pin != second.Pin || !reflect.DeepEqual(original, stage()) {
		t.Fatal("same Runtime DB/source/native ID/pins", err, err2)
	}
	catalog, _ = policy.Catalog(read().State)
	tenant, _ = catalog.Tenant("tenant")
	change("revoke-node", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, nil))
	denied, denyErr := call(nodeMesh, runtime.Identity, "app-native-permit", request)
	if denyErr == nil && denied.Code == "ok" {
		t.Fatal("revoked node got new activation authority")
	}
	if id, e := runtime.network.Inspect(ctx, key); e != nil || id != native {
		t.Fatal("revocation erased existing native resource", e)
	}
	if a, e := policy.Apps(read().State); e != nil {
		t.Fatal(e)
	} else if execution, _ := a.Execution("tenant", "app"); execution.Status() == "Succeeded" {
		t.Fatal("unsupported task marked whole app succeeded")
	}
	t.Log("actual managed Runtime -> accepted user app -> exact Prepare/Send/Goal/Collect -> SDK/kernel Bridge -> signed observation; live consumer shrink; member-only fresh SFCP permit/result; Snapshot/same DB/native ID/pins; revoked activation retains original resource; task pending")
}

func containsBridgeKey(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}
