// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/tests/gitfixture"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

func nativeGitRevision(t *testing.T, raw []byte, revision string, policy *deployment.DeliveryDeclaration) []byte {
	return nativeGitServiceRevision(t, raw, revision, policy, "endpoint")
}

func nativeGitServiceRevision(t *testing.T, raw []byte, revision string, policy *deployment.DeliveryDeclaration, name string) []byte {
	t.Helper()
	app, err := deployment.ParseApp(raw)
	if err != nil {
		t.Fatal(err)
	}
	if policy != nil {
		p := *policy
		app.Sfc.Delivery = &p
	}
	service, found := app.Services[name]
	if !found {
		t.Fatal("original native sample endpoint missing")
	}
	if service.Environment == nil {
		service.Environment = deployment.Environment{}
	}
	service.Environment["REVISION"] = revision
	app.Services[name] = service
	body, err := yaml.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	// The source really crosses the existing bounded multipart Upload. The
	// padding is only Git blob content, not a custom parser or transport limit.
	return append(body, []byte(strings.Repeat("# native source multipart\n", 1400))...)
}

func prepareNativeGitDocument(t *testing.T, raw []byte, repository string) []byte {
	t.Helper()
	app, err := deployment.ParseApp(raw)
	if err != nil {
		t.Fatal(err)
	}
	service, found := app.Services["endpoint"]
	if !found {
		t.Fatal("original native sample endpoint missing")
	}
	command := deployment.Arguments{"/backend"}
	service.Command = &command
	if service.Environment == nil {
		service.Environment = deployment.Environment{}
	}
	service.Environment["SFC_READINESS_FIXTURE"] = "1"
	service.Sfc.Readiness = &deployment.Readiness{Kind: "http", Path: "/readyz", Port: 8080, Timeout: "1s"}
	app.Services["endpoint"] = service
	raw, err = yaml.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	p := nativeGitPolicy(repository)
	return nativeGitRevision(t, raw, "1", &p)
}

func nativeGitPolicy(repository string) deployment.DeliveryDeclaration {
	var p deployment.DeliveryDeclaration
	p.Enabled = true
	p.Source.Kind, p.Source.Repository, p.Source.Ref, p.Source.Path, p.Source.Credential = "git", repository, "refs/heads/main", "app.yaml", "git-read"
	p.Poll, p.Limits.Fetch, p.Limits.Bytes, p.Limits.Queued, p.Limits.Active = 5, 10, 4<<20, 1, 1
	p.Sync.Mode, p.Sync.Drift = "manual", "report"
	p.Runtime.Mode, p.Runtime.Expiry = "require-explicit-override", "manual-release"
	return p
}

// Extends the already-owned source/managed two-control fixture, using its real
// CLI/profile/user, original Managers, namespace/native and rollback. The Git
// fixture is only a remote HTTPS server; no candidate/result is injected here.
func verifyNativeGitDelivery(t *testing.T, ctx context.Context, owners *[2]*Runtime, root string, source *gitfixture.Fixture, original []byte, firstCommit string, policy control.Policy, read func() cluster.View, cli func(...string) []byte, change func(string, string, uint64, any), wait func(string, func() bool), lead func(int), restart func(int), user userauth.Client, session access.Session, peers []sfcp.Peer, registry string) map[string]any {
	t.Helper()
	defer func() {
		if !t.Failed() {
			return
		}
		t.Log("original Git remote observations", source.Stats())
		for i, owner := range owners {
			if owner == nil {
				continue
			}
			owner.mu.RLock()
			cause := owner.moduleError
			owner.mu.RUnlock()
			t.Log("original CD owner cause", i, cause, "active source IO", owner.deliverySourceActive.Load())
			if v, err := owner.Engine().Read(context.Background(), false); err == nil {
				if apps, err := policy.Apps(v.State); err == nil {
					for _, row := range apps.Records() {
						if row.App == "next" {
							t.Log("original public CD selection", row.CD)
						}
					}
				}
			}
		}
	}()
	key := deployment.ResourceKey("task", "tenant", "next", "endpoint")
	docker, err := engine.Open(ctx, (*owners)[0].installation.config.EngineEndpoint(), (*owners)[0].owner)
	if err != nil {
		t.Fatal(err)
	}
	defer docker.Close()
	delivery := func() (control.Apps, deployment.Delivery) {
		t.Helper()
		apps, err := policy.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		d, found := apps.Delivery("tenant", "next")
		if !found {
			t.Fatal("Git registration was not attached to the ordinary app Inventory")
		}
		return apps, d
	}
	candidate := func(commit string) bool {
		_, d := delivery()
		choice, found := d.CandidateSelection()
		return found && choice.Commit == commit && d.SourceError() == ""
	}
	running := func(commit, revision string) bool {
		apps, d := delivery()
		selected, found := d.Selection()
		execution, active := apps.Execution("tenant", "next")
		if !found || !active || selected.Commit != commit || execution.ActiveOperation() != selected.Operation || execution.Status() != "Succeeded" {
			return false
		}
		status, err := (*owners)[0].workload.Status(ctx, key)
		if err != nil || !status.Ready || !status.Running || status.NativeID == "" {
			return false
		}
		got, err := docker.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
		return err == nil && got.Container.Config != nil && slices.Contains(got.Container.Config.Env, "REVISION="+revision)
	}
	registration := func() [32]byte {
		t.Helper()
		apps, _ := delivery()
		op, found := apps.CDRegistration("tenant", "next")
		if !found {
			t.Fatal("original signed CD registration missing")
		}
		raw, err := json.Marshal(op)
		if err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(raw)
	}
	originalRegistration := registration()
	wait("actual HTTPS Git registration/candidate", func() bool { return candidate(firstCommit) })
	_, d := delivery()
	manualPolicy := d.Policy()
	if os.Getenv("SFC_TEST_RQ4_CD") == "1" {
		return verifyCDCandidateDecisionNative(t, ctx, owners, source, original, manualPolicy, key, cli, wait, delivery, candidate, running, root, user, peers[0], change)
	}
	secondCommit := source.Commit(nativeGitRevision(t, original, "2", &manualPolicy))
	wait("actual multipart source candidate", func() bool { return candidate(secondCommit) })
	_, d = delivery()
	selected, found := d.CandidateSelection()
	if !found {
		t.Fatal("second Git candidate missing")
	}
	cli("cd", "sync", "next", "--tenant", "tenant", "--id", "git-manual-operation", "--candidate", hex.EncodeToString(selected.Candidate[:]))
	wait("manual Git sync actual native change", func() bool { return running(secondCommit, "2") })
	cli("op", "show", "git-manual-operation")
	// Repeating an already retained ID continues its saved original; it
	// cannot fetch/sign a different candidate or issue a new deployment ID.
	cli("cd", "sync", "next", "--tenant", "tenant", "--id", "git-manual-operation")
	manualState, err := (*owners)[0].workload.Status(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	statsBefore := source.Stats()
	source.Mode("unauthorized")
	wait("fresh Git credential failure despite cached objects", func() bool {
		_, d := delivery()
		return source.Stats().Denied > statsBefore.Denied && d.SourceError() != ""
	})
	failedState, err := (*owners)[0].workload.Status(ctx, key)
	if err != nil || !failedState.Running || failedState.NativeID != manualState.NativeID || failedState.StartedAt != manualState.StartedAt {
		t.Fatal("source authentication failure replaced/stopped the original native", err)
	}
	stateBytes, err := state.Encode(read().State)
	if err != nil || bytes.Contains(stateBytes, []byte("private-fixture-auth-detail")) || bytes.Contains(stateBytes, []byte("private-native-git-fixture-token")) {
		t.Fatal("private Git provider detail reached the shared state", err)
	}
	source.Mode("")
	wait("authenticated source recovery with original cache", func() bool { return candidate(secondCommit) })
	// Keep the real process alive while its declared readiness fails. Observe
	// the owner's signed failure before enabling automatic delivery, so a stale
	// healthy report cannot make the next commit appear safely deployable.
	object := read().State.Object(key)
	target, err := (*owners)[0].workload.ProbeTarget(ctx, key, object.Generation, object.Revision)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second}
	defer httpClient.CloseIdleConnections()
	setReady := func(call context.Context, ready bool) error {
		value := "0"
		if ready {
			value = "1"
		}
		req, err := http.NewRequestWithContext(call, http.MethodGet, "http://"+target.IPv4.String()+":8080/readiness-state?ready="+value, nil)
		if err != nil {
			return err
		}
		response, err := httpClient.Do(req)
		if err != nil {
			return err
		}
		_, drainErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusNoContent || drainErr != nil || closeErr != nil {
			return fmt.Errorf("original readiness toggle: status=%d drain=%v close=%v", response.StatusCode, drainErr, closeErr)
		}
		return nil
	}
	readinessHeld := true
	defer func() {
		if readinessHeld {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := setReady(cleanup, true); err != nil {
				t.Error("restore original readiness before native rollback", err)
			}
		}
	}()
	if err := setReady(ctx, false); err != nil {
		t.Fatal(err)
	}
	wait("actual signed unready observation of the still-running original", func() bool {
		apps, _ := delivery()
		execution, found := apps.Execution("tenant", "next")
		return found && execution.ActiveOperation() == "git-manual-operation" && execution.Health(uint64(time.Now().Unix())) == "Degraded"
	})
	automaticFile := deployment.CDFileOf(manualPolicy)
	automaticFile.Sync = "auto"
	policyFile := filepath.Join(root, "automatic-cd.yaml")
	rawPolicy, err := yaml.Marshal(automaticFile)
	if err != nil {
		t.Fatal(err)
	}
	// The policy the Git revisions embed is what cd.yaml sets on the server.
	automatic, err := deployment.ParseCDFile(rawPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyFile, rawPolicy, 0600); err != nil {
		t.Fatal(err)
	}
	cli("cd", "set", "next", "--tenant", "tenant", "--id", "git-automatic-policy", "-f", policyFile)
	lead(0)
	thirdCommit := source.Commit(nativeGitRevision(t, original, "3", &automatic))
	lead(1) // actual SDK handoff while the next registered source is selected
	wait("actual automatic health gate survives control handoff", func() bool {
		v := read()
		work, err := policy.AppDeliverySyncWork(v.State, (*owners)[1].Identity.Public, control.AppDeliveryWorkRequest{Tenant: "tenant", App: "next", At: uint64(time.Now().Unix())})
		_, d := delivery()
		selection, found := d.Selection()
		return err == nil && work.Action == "" && work.Reason == "original-health-or-work" && candidate(thirdCommit) && found && selection.Operation == "git-manual-operation" && selection.Commit == secondCommit
	})
	healthBlocked, err := (*owners)[0].workload.Status(ctx, key)
	if err != nil || !healthBlocked.Running || healthBlocked.Ready || healthBlocked.NativeID != manualState.NativeID || healthBlocked.StartedAt != manualState.StartedAt {
		t.Fatal("health gate replaced/stopped the running original", err)
	}
	if err := setReady(ctx, true); err != nil {
		t.Fatal(err)
	}
	readinessHeld = false
	wait("automatic Git selection after actual control handoff", func() bool { return running(thirdCommit, "3") })
	_, d = delivery()
	third, found := d.Selection()
	if !found || third.Operation == "git-manual-operation" || third.Commit != thirdCommit {
		t.Fatal("automatic selection lost original source/operation identity")
	}
	if registration() != originalRegistration {
		t.Fatal("sync/configuration/handoff rewrote the signed registration")
	}
	// A new Git revision cannot become a committed candidate/execution while
	// an actual two-voter cluster has only one available control. The old native
	// keeps running independently of the stopped owner's runtime/transport.
	beforeLoss, err := (*owners)[0].workload.Status(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := (*owners)[0].Close(); err != nil {
		t.Fatal(err)
	}
	(*owners)[0] = nil
	fourthCommit := source.Commit(nativeGitRevision(t, original, "4", &automatic))
	probe, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	_, err = user.Query(probe, peers[1], session, "apps", "tenant")
	cancel()
	if err == nil {
		t.Fatal("CD latest quorum read succeeded with only one of two voters")
	}
	v, err := (*owners)[1].Engine().Read(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	retainedApps, err := policy.Apps(v.State)
	retained, retainedOK := retainedApps.Delivery("tenant", "next")
	retainedSelection, selectedOK := retained.Selection()
	if err != nil || !retainedOK || !selectedOK || retainedSelection.Operation != third.Operation || retainedSelection.Commit != thirdCommit {
		t.Fatal("quorum loss changed the accepted CD operation", err)
	}
	got, err := docker.API.ContainerInspect(ctx, beforeLoss.NativeID, client.ContainerInspectOptions{})
	if err != nil || got.Container.State == nil || !got.Container.State.Running || got.Container.State.StartedAt != beforeLoss.StartedAt {
		t.Fatal("control outage was treated as terminal native evidence", err)
	}
	restart(0)
	wait("original DB/control recovery and fourth Git operation", func() bool { return running(fourthCommit, "4") })
	// The image is already cached. Current tenant trust still blocks the next
	// source/native admission; withdrawal cannot erase the accepted operation.
	catalog, err := policy.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	withdrawn := slices.DeleteFunc(slices.Clone(tenant.ImageSources), func(rule access.TrustRule) bool { return rule.Registry != registry })
	beforeTrust, err := (*owners)[0].workload.Status(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	change("git-withdraw-current-image-trust", "set-trust", tenant.Revision, control.TrustChange{Tenant: "tenant", Remove: withdrawn})
	fifthCommit := source.Commit(nativeGitRevision(t, original, "5", &automatic))
	wait("current trust blocks the next cached-image source", func() bool {
		_, d := delivery()
		choice, _ := d.Selection()
		return d.SourceError() != "" && choice.Commit != fifthCommit
	})
	afterTrust, err := (*owners)[0].workload.Status(ctx, key)
	if err != nil || afterTrust.NativeID != beforeTrust.NativeID || afterTrust.StartedAt != beforeTrust.StartedAt || !afterTrust.Running {
		t.Fatal("current trust withdrawal destroyed original execution", err)
	}
	catalog, err = policy.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ = catalog.Tenant("tenant")
	change("git-restore-explicit-image-trust", "set-trust", tenant.Revision, control.TrustChange{Tenant: "tenant", Add: withdrawn})
	wait("restored current trust admits the fifth source", func() bool { return running(fifthCommit, "5") })
	cli("cd", "override", "next", "services/endpoint/environment/REVISION", `"operator"`, "--tenant", "tenant", "--id", "git-field-override")
	wait("explicit field override actual native value", func() bool {
		status, err := (*owners)[0].workload.Status(ctx, key)
		if err != nil || !status.Ready {
			return false
		}
		got, err := docker.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
		return err == nil && got.Container.Config != nil && slices.Contains(got.Container.Config.Env, "REVISION=operator")
	})
	sixthCommit := source.Commit(nativeGitRevision(t, original, "6", &automatic))
	wait("source revision respects explicit field ownership", func() bool {
		// Candidate arrival and the previous native's Ready are insufficient:
		// the automatic operation for this exact commit must finish before an
		// explicit ownership release is allowed by overrideIdle.
		if !running(sixthCommit, "operator") {
			return false
		}
		_, d := delivery()
		choice, found := d.CandidateSelection()
		if !found || choice.Commit != sixthCommit || len(d.Overrides()) != 1 {
			return false
		}
		status, err := (*owners)[0].workload.Status(ctx, key)
		if err != nil || !status.Ready {
			return false
		}
		got, err := docker.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
		return err == nil && got.Container.Config != nil && slices.Contains(got.Container.Config.Env, "REVISION=operator")
	})
	cli("cd", "field", "next", "services/endpoint/environment/REVISION", "--tenant", "tenant")
	cli("cd", "release", "next", "services/endpoint/environment/REVISION", "--tenant", "tenant", "--id", "git-field-release")
	wait("explicit field return consumes the latest frozen Git revision", func() bool { return running(sixthCommit, "6") })
	if registration() != originalRegistration {
		t.Fatal("field override/return replaced the original source registration")
	}
	// This control has no native workload. Its actual in-flight source read
	// alone must keep isolation pending; a missing reply is not a zero census.
	lead(1)
	gate := source.HoldNextPack()
	defer gate.Release()
	seventhCommit := source.Commit(nativeGitRevision(t, original, "7", &automatic))
	wait("actual source HTTPS request held", func() bool {
		select {
		case <-gate.Entered:
			return true
		default:
			return false
		}
	})
	reader := (*owners)[1]
	activity, err := reader.nodeLocalActivity(ctx)
	if err != nil || reader.deliverySourceActive.Load() == 0 || activity.CDJobs == 0 {
		t.Fatal("real source IO disappeared from the local owner census", activity, err)
	}
	directory, err := policy.Members(read().State)
	if err != nil {
		t.Fatal(err)
	}
	topology, err := directory.Topology()
	if err != nil {
		t.Fatal(err)
	}
	nodeID := reader.installation.record.Root.Self.ID
	node, found := topology.Node(nodeID)
	if !found {
		t.Fatal("actual source reader not installed")
	}
	change("isolate-active-git-reader", "isolate-node", node.Revision, control.NodeLifecycleChange{ID: nodeID, Operation: "isolate-git-reader", Epoch: topology.Epoch()})
	directory, err = policy.Members(read().State)
	nodeView, found := directory.NodeView(nodeID)
	if err != nil || !found || nodeView.Node.Phase != lifecycle.Isolating || nodeView.Node.Closure != nil || directory.WorkKey(reader.Identity.Public) || reader.deliverySourceActive.Load() == 0 {
		t.Fatal("in-flight Git read became an isolated zero-activity owner", err)
	}
	gate.Release()
	wait("actual local source IO closes before runtime isolation proof", func() bool {
		directory, err := policy.Members(read().State)
		view, found := directory.NodeView(nodeID)
		return err == nil && found && view.Node.Phase == lifecycle.Isolated && view.Node.Closure != nil && view.Node.Closure.Closed && reader.deliverySourceActive.Load() == 0
	})
	wait("original shared source ticket is explicitly settled", func() bool {
		_, d := delivery()
		_, pending := d.FetchTicket()
		return !pending && d.SourceError() == "policy"
	})
	directory, err = policy.Members(read().State)
	if err != nil {
		t.Fatal(err)
	}
	topology, err = directory.Topology()
	if err != nil {
		t.Fatal(err)
	}
	nodeView, _ = directory.NodeView(nodeID)
	closedReader := *nodeView.Node.Closure
	change("restore-original-git-reader", "restore-node", nodeView.Node.Revision, control.NodeLifecycleChange{ID: nodeID, Operation: "restore-git-reader", Epoch: topology.Epoch()})
	wait("fresh original-key source reader readiness", func() bool {
		directory, err := policy.Members(read().State)
		view, found := directory.NodeView(nodeID)
		return err == nil && found && view.Node.Phase == lifecycle.Active && view.Node.Closure != nil && view.Node.Closure.Ready && directory.WorkKey(reader.Identity.Public)
	})
	wait("restored current reader consumes the seventh revision", func() bool { return running(seventhCommit, "7") })
	cli("cd", "show", "next", "--tenant", "tenant")
	stats := source.Stats()
	if stats.Advertisements < 2 || stats.Packs < 2 || stats.Denied == 0 || !slices.Contains(stats.Wants, secondCommit) || !slices.Contains(stats.Wants, sixthCommit) {
		t.Fatal("missing actual HTTPS/auth/commit fetch evidence", stats)
	}
	return map[string]any{"registration": fmt.Sprintf("%x", originalRegistration), "commits": []string{firstCommit, secondCommit, thirdCommit, fourthCommit, fifthCommit, sixthCommit, seventhCommit}, "manual_operation": "git-manual-operation", "automatic_third_operation": third.Operation, "health_blocked_original": healthBlocked, "source": stats, "reader_closure": closedReader, "scope": "actual HTTPS Git/multipart/User CLI/manual+automatic/declared HTTP readiness/SDK handoff/N2 outage/current trust/field override/source-reader isolate+restore; same ordinary native owner and inventory"}
}
