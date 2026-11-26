// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload"
	"gopkg.in/yaml.v3"
)

// This real Engine boundary enables only the new metadata delegation adapter.
// Native modules/projectors/controller are deliberately absent. Signed owner
// observations below are fixtures; they are not proof of Docker/kernel effects.
func TestRealAppExecutionOriginalDelegationJournalAndSameDB(t *testing.T) {
	testRealAppExecution(t, "")
}

func TestRealAppReportLifetimeRaftSnapshotAndSameDB(t *testing.T) {
	testRealAppExecution(t, "lifetime")
}

func TestRealControlOnlyLeaderAdvancesDeliveryMetadataWithoutNativeAdapters(t *testing.T) {
	testRealAppExecution(t, "delivery-metadata")
}

func TestRealManagedPassCollectionDoesNotStarveNextApp(t *testing.T) {
	testRealAppExecution(t, "managed-pass-progress")
}

func TestRealDeliveryTenantQueriesAndMutationUseCurrentMembership(t *testing.T) {
	testRealAppExecution(t, "delivery-tenant-auth")
}

func TestRealDeliveryAuthorityUncertaintyKeepsOriginalPartialInput(t *testing.T) {
	testRealAppExecution(t, "delivery-source-uncertainty")
}

func TestRealRetirementExplicitOriginalReplay(t *testing.T) {
	for _, mode := range []string{"retirement-replay", "retirement-replay-late"} {
		t.Run(mode, func(t *testing.T) { testRealAppExecution(t, mode) })
	}
}

func testRealAppExecution(t *testing.T, reportMode string) {
	deliveryMetadata := reportMode == "delivery-metadata" || reportMode == "delivery-tenant-auth" || reportMode == "managed-pass-progress" || reportMode == "delivery-source-uncertainty" || strings.HasPrefix(reportMode, "retirement-replay")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	root := t.TempDir()
	key := func(id string) *identity.Identity {
		t.Helper()
		k, e := identity.Create(filepath.Join(root, id))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { clear(k.Private) })
		return k
	}
	node, admin, proof := key("node"), key("admin"), key("proof")
	clusterID := [32]byte{98}
	peer := mydcp.Peer{ID: "node-a", Policy: mydcp.Policy{Key: mydcp.Identity(node.Public), Member: true, Read: true, Respond: true, Snapshot: true, Replicate: true}}
	lookup := func(k mydcp.Identity) (mydcp.Peer, bool) {
		if k == peer.Key {
			return peer, true
		}
		return mydcp.Peer{ID: hex.EncodeToString(k[:]), Policy: mydcp.Policy{Key: k, UserAuth: true, Respond: true}}, true
	}
	mesh, e := mydcp.NewTransport(node, clusterID, lookup)
	if e != nil {
		t.Fatal(e)
	}
	if e = mesh.Listen("127.0.0.1:0"); e != nil {
		t.Fatal(e)
	}
	peer.Endpoint = mesh.Addr().String()
	policy := control.Policy{Cluster: clusterID, BootstrapKey: admin.Public, TrustRoot: node.Public, Genesis: config.Peer{ID: peer.ID, Key: node.Actor(), Endpoint: peer.Endpoint, Voter: true}}
	options := cluster.Options{ID: peer.ID, Root: filepath.Join(root, "state"), Admin: admin.Actor(), Cluster: clusterID, Mesh: mesh, Bootstrap: true, Validate: policy.Validate, Reduce: policy.Reduce, AdmitModule: policy.AdmitModule, AdmitMutation: policy.AdmitAppMutation, ModuleID: policy.ID(), Servers: []raft.Server{{ID: raft.ServerID(peer.ID), Address: raft.ServerAddress(peer.Endpoint), Suffrage: raft.Voter}}}
	options.AdmitModulePatch = policy.AdmitAppPatch
	options.Resolve = func(id raft.ServerID, address raft.ServerAddress) (mydcp.Peer, bool) {
		return peer, string(id) == peer.ID && string(address) == peer.Endpoint
	}
	options.CommandModule = func(method, caller string, input []byte, view cluster.View) (state.Command, error) {
		key, err := identity.ParseKey(caller)
		if err != nil {
			return state.Command{}, err
		}
		return policy.ResolveAppCommand(view.State, method, key, input)
	}
	options.ReadModule = func(_ context.Context, method, caller string, input []byte, view cluster.View) (json.RawMessage, error) {
		if method != "app-result" {
			return nil, mydcp.ErrAdmission
		}
		key, err := identity.ParseKey(caller)
		if err != nil {
			return nil, err
		}
		cmd, err := state.DecodeCommand(input)
		if err != nil {
			return nil, err
		}
		result, err := policy.AppResult(view.State, key, cmd)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	var engine *cluster.Engine
	defer func() {
		if engine != nil {
			_ = engine.Close()
		}
		_ = mesh.Close()
	}()
	open := func() {
		t.Helper()
		var err error
		options.Mesh = mesh
		engine, err = cluster.Open(options)
		if err != nil {
			t.Fatal(err)
		}
		if err = engine.ServeManagement(); err != nil {
			t.Fatal(err)
		}
		if err = (userauth.Service{Engine: engine, Mesh: mesh, Self: node, Policy: policy}).Serve(); err != nil {
			t.Fatal(err)
		}
	}
	open()
	read := func() state.State {
		t.Helper()
		for {
			v, err := engine.Read(ctx, true)
			if err == nil {
				return v.State
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	_ = read()
	clientMesh, e := mydcp.NewTransport(proof, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) { return peer, k == peer.Key })
	if e != nil {
		t.Fatal(e)
	}
	defer clientMesh.Close()
	client := userauth.Client{Mesh: clientMesh, Self: proof, Cluster: clusterID, Peers: []mydcp.Peer{peer}}
	memberMesh, e := mydcp.NewTransport(node, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) { return peer, k == peer.Key })
	if e != nil {
		t.Fatal(e)
	}
	defer memberMesh.Close()
	memberCall := func(method string, raw []byte) cluster.ManagementReply {
		t.Helper()
		reply, err := cluster.CallManagement(ctx, memberMesh, node, clusterID, peer, cluster.ManagementRequest{Method: method, Latest: true, Input: raw})
		if err != nil {
			t.Fatal(method, reply.Code, err)
		}
		return reply
	}
	enrolled, e := client.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "enroll-app-execution", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}}}, admin.Private)
	if e != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("actual enroll", e)
	}
	session, e := client.Login(ctx, peer, "admin", admin.Private)
	if e != nil {
		t.Fatal(e)
	}
	userOp := func(id, action string, expected uint64, payload any, want ...state.Code) state.Result {
		t.Helper()
		raw, err := control.ChangeBytes(action, "admin", expected, payload)
		if err != nil {
			t.Fatal(err)
		}
		var ch control.Change
		_ = json.Unmarshal(raw, &ch)
		op, err := client.Prepare(ctx, peer, session, id, ch)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := client.Operation(ctx, peer, op, false)
		expectedCode := state.Applied
		if len(want) > 0 {
			expectedCode = want[0]
		}
		if err != nil || reply.Result == nil || reply.Result.Code != expectedCode {
			t.Fatal("user operation", id, reply.Code, reply.Result, err)
		}
		return *reply.Result
	}
	catalog := func() access.Catalog {
		t.Helper()
		c, err := policy.Catalog(read())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	apps := func() control.Apps {
		t.Helper()
		a, err := policy.Apps(read())
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	execution := func() deployment.Execution {
		t.Helper()
		ex, ok := apps().Execution("tenant", "app")
		if !ok {
			t.Fatal("missing execution")
		}
		return ex
	}
	inventoryRevision := func(appName string) uint64 {
		t.Helper()
		a := apps()
		page, _, err := a.Page(catalog(), "admin", "tenant", "")
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range page {
			if v.App == appName {
				return v.Revision
			}
		}
		t.Fatal("missing app", appName)
		return 0
	}

	apply := func(cmd state.Command, want state.Code) state.Result {
		t.Helper()
		c, err := engine.Submit(ctx, cmd)
		if err != nil || c.Result.Code != want {
			t.Fatal("commit", cmd.RequestID, c.Result, want, err)
		}
		return c.Result
	}
	counter := 0
	progress := func(action, key string, observation *deployment.Observation, want state.Code, target ...string) state.Command {
		t.Helper()
		counter++
		appName := "app"
		if len(target) > 0 {
			appName = target[0]
		}
		s := read()
		r := control.AppProgress{Schema: 1, Cluster: clusterID, Reporter: node.Public, Tenant: "tenant", App: appName, Operation: "rollout", Action: action, Key: key, Expected: inventoryRevision(appName), At: uint64(time.Now().Unix()), Observation: observation, Epoch: s.ModuleEpoch(), RequestID: fmt.Sprintf("progress-%d", counter), RootRevision: s.Object(control.AppsKey).Revision}
		if control.StageReport(r.Action) {
			r.Stage = policy.StageDigest(s, r.Tenant, r.App, r.Key)
		}
		r.Signature = ed25519.Sign(node.Private, control.AppProgressBytes(r))
		cmd, err := r.Command()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(r)
		reply := memberCall("app-progress", raw)
		if reply.Committed == nil || reply.Committed.Result.Code != want {
			t.Fatal("member progress", action, reply.Committed, want)
		}
		return cmd
	}
	userOp("tenant", "create-tenant", 0, control.TenantID{ID: "tenant"})
	tenant, _ := catalog().Tenant("tenant")
	userOp("nodes", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: []string{peer.ID}})
	for i, scope := range []string{"", "tenant"} {
		limit := tenancy.NodeLimit{Tenant: scope, Node: peer.ID, Capacity: workload.Resources{CPU: 1e9, Memory: 256 << 20}, Networks: 2, MaxConsumers: 8}
		userOp(fmt.Sprintf("limit%d", i), "set-node-quota", 0, limit)
	}
	document := []byte("name: app\nservices:\n web:\n  image: docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "\n  cpus: 0.1\n  mem_limit: 16m\n  networks: {app: {ipv4_address: 10.86.0.10}}\n  x-mydc: {node: node-a}\nnetworks:\n app:\n  x-mydc: {mtu: 1280, pools: {node-a: {cidr: 10.86.0.0/24, gateway: 10.86.0.1}}}\n")
	{
		resources, err := policy.Resources(read())
		if err != nil {
			t.Fatal(err)
		}
		userOp("management-network", "create-tun-network", resources.Networks.Revision(), tenancy.TUNDefinition{Tenant: "tenant", Name: "existing", Members: []tenancy.TUNNode{{Node: peer.ID, Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.86.0.0/24"), Gateway: netip.MustParseAddr("10.86.0.1"), MTU: 1280}}, Addresses: []netip.Prefix{netip.MustParsePrefix("10.87.0.1/32")}}}})
		document = bytes.Replace(document, []byte("networks:\n app:\n  x-mydc: {mtu: 1280, pools: {node-a: {cidr: 10.86.0.0/24, gateway: 10.86.0.1}}}\n"), []byte("networks:\n app: {external: true, name: existing}\n"), 1)
	}
	if deliveryMetadata {
		app, err := deployment.ParseApp(document)
		if err != nil {
			t.Fatal(err)
		}
		cd := nativeGitPolicy("https://example.test/repo.git")
		app.MyDC.Delivery = &cd
		document, err = yaml.Marshal(app)
		if err != nil {
			t.Fatal(err)
		}
	}
	reply, e := client.PlanApp(ctx, peer, session, "tenant", control.AppPlanRequest{Document: document})
	if e != nil || reply.AppPlan == nil || reply.AppPlan.Length != len(reply.AppPlan.Data) {
		t.Fatal("small actual plan", e)
	}
	plan, e := deployment.DecodeBlueprint(reply.AppPlan.Data)
	if e != nil {
		t.Fatal(e)
	}
	wantSteps := 2
	if deliveryMetadata {
		wantSteps = 3
	}
	if len(plan.Steps()) != wantSteps {
		t.Fatal("fixture graph", len(plan.Steps()))
	}
	userOp("upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: "tenant", App: "app", Deployment: "app", ID: "artifact", Length: reply.AppPlan.Length, Digest: sha256.Sum256(reply.AppPlan.Data)})
	userOp("part", "put-app-part", 1, control.AppUploadPart{Tenant: "tenant", ID: "artifact", Data: reply.AppPlan.Data})
	userOp("begin", "begin-app", 0, control.AppBegin{Tenant: "tenant", App: "app", Deployment: "app", Upload: "artifact", Operation: "rollout"})
	if reportMode == "managed-pass-progress" {
		// Actual authenticated N1/Raft/DB boundary, without Docker/kernel
		// effects. Collecting one app's committed result must not suppress
		// preparing the next eligible app in that same successful pass.
		second, err := deployment.ParseApp(document)
		if err != nil {
			t.Fatal(err)
		}
		second.Name = "second"
		web := second.Services["web"]
		attachment := web.Networks["app"]
		attachment.IPv4 = "10.86.0.11"
		web.Networks["app"] = attachment
		second.Services["web"] = web
		body, err := yaml.Marshal(second)
		if err != nil {
			t.Fatal(err)
		}
		planned, err := client.PlanApp(ctx, peer, session, "tenant", control.AppPlanRequest{Document: body})
		if err != nil || planned.AppPlan == nil {
			t.Fatal("second real app plan", err)
		}
		userOp("upload-second", "begin-app-upload", 0, control.AppUploadBegin{Tenant: "tenant", App: "second", Deployment: "second", ID: "second-artifact", Length: planned.AppPlan.Length, Digest: sha256.Sum256(planned.AppPlan.Data)})
		userOp("part-second", "put-app-part", 1, control.AppUploadPart{Tenant: "tenant", ID: "second-artifact", Data: planned.AppPlan.Data})
		userOp("begin-second", "begin-app", 0, control.AppBegin{Tenant: "tenant", App: "second", Deployment: "second", Upload: "second-artifact", Operation: "second-rollout"})
		var installation managedInstallation
		installation.record.Root.Self.ID = peer.ID
		r := &Runtime{Identity: node, Mesh: mesh, engine: engine, controlPolicy: policy, installation: &installation, ctx: ctx}
		for range 2 {
			if err := r.advanceCurrentApps(ctx); err != nil {
				t.Fatal("prepare/send original metadata", err)
			}
		}
		metadata := func(app string) deployment.StageRecord {
			t.Helper()
			x, ok := apps().Execution("tenant", app)
			if !ok {
				t.Fatal("missing original execution", app)
			}
			for _, step := range x.Steps() {
				if step.Kind == "delivery" {
					st, _ := x.Stage(step.Key)
					return st
				}
			}
			t.Fatal("missing metadata stage", app)
			return deployment.StageRecord{}
		}
		first := metadata("app")
		if first.Command == nil || first.Result != nil {
			t.Fatal("fixture requires a committed but uncollected original")
		}
		if result, found := read().LookupResult(*first.Command); !found || result.Code != state.Applied {
			t.Fatal("original metadata not committed")
		}
		if metadata("second").Command != nil {
			t.Fatal("fixture advanced second app early")
		}
		// A failed owner pass cannot grant a metadata progress opportunity.
		// The existing recovery guard rejects this missing observation DB.
		r.workload = &workload.Manager{}
		if err := r.reconcileManaged(cluster.View{State: read()}); err == nil {
			t.Fatal("unavailable owner journal was ignored")
		}
		if metadata("app").Result != nil || metadata("second").Command != nil {
			t.Fatal("failed owner pass advanced metadata")
		}
		r.workload = nil
		if err := r.reconcileManaged(cluster.View{State: read()}); err != nil {
			t.Fatal("successful managed pass", err)
		}
		if metadata("app").Result == nil || metadata("app").Result.Code != state.Applied {
			t.Fatal("first original result not collected")
		}
		if metadata("second").Command == nil {
			t.Fatal("result collection starved next eligible app")
		}
		for _, app := range []string{"app", "second"} {
			x, _ := apps().Execution("tenant", app)
			for _, step := range x.Steps() {
				st, _ := x.Stage(step.Key)
				if step.Kind != "delivery" && st.Command != nil {
					t.Fatal("control-only pass created native work", app, step.Key)
				}
			}
		}
		return
	}
	if deliveryMetadata {
		var installation managedInstallation
		installation.record.Root.Self.ID = peer.ID // reply routing, not authority
		r := &Runtime{Identity: node, Mesh: mesh, engine: engine, controlPolicy: policy, installation: &installation, ctx: ctx}
		collected := false
		for n := 0; n < 4; n++ {
			changed, err := r.collectAppResults(ctx, cluster.View{State: read()}, apps())
			if err != nil {
				t.Fatal("early original result collection", err)
			}
			if changed {
				collected = true
				continue
			}
			if err := r.advanceCurrentApps(ctx); err != nil {
				t.Fatal("control-only metadata progress", err)
			}
		}
		if !collected {
			t.Fatal("durable result required native reconciliation")
		}
		for _, step := range execution().Steps() {
			stage, _ := execution().Stage(step.Key)
			if step.Kind == "delivery" {
				if stage.Command == nil || stage.Result == nil || stage.Result.Code != state.Applied {
					t.Fatal("leader without network did not commit/collect its original metadata", stage.Result)
				}
				if result, found := read().LookupResult(*stage.Command); !found || result != *stage.Result {
					t.Fatal("metadata lacks its original durable receipt")
				}
			} else if stage.Command != nil || stage.Result != nil {
				t.Fatal("control without native adapters dispatched native work", step.Key)
			}
		}
		if execution().Status() == "Succeeded" {
			t.Fatal("metadata commit impersonated native completion")
		}
		if strings.HasPrefix(reportMode, "retirement-replay") {
			verifyRealRetirementReplay(t, ctx, r, read, userOp, reportMode == "retirement-replay-late")
			return
		}
		if reportMode == "delivery-source-uncertainty" {
			verifyRealDeliveryAuthorityUncertainty(t, ctx, r, func(revision uint64) {
				userOp("pause-source-authority", "pause-app-cd", revision, control.AppCDChange{Tenant: "tenant", App: "app"})
			})
		}
		if reportMode == "delivery-tenant-auth" {
			manager := key("manager")
			userOp("cd-manager-account", "put-user", 0, access.User{ID: "manager", Username: "manager", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: manager.Public, Enabled: true}}})
			userOp("cd-manager-membership", "set-membership", 0, access.Membership{Tenant: "tenant", User: "manager", Role: access.Manager, Enabled: true})
			userOp("cd-other-tenant", "create-tenant", 0, control.TenantID{ID: "other"})
			managerSession, err := client.Login(ctx, peer, "manager", manager.Private)
			if err != nil {
				t.Fatal("actual CD manager login", err)
			}
			q := control.AppCDFieldRequest{App: "app", Path: []string{"services", "web", "cpus"}}
			if _, err := client.AppDeliveryField(ctx, peer, managerSession, "tenant", q); err != nil {
				t.Fatal("own tenant CD field query", err)
			}
			denied := func(err error) bool {
				var e *userauth.Error
				return errors.As(err, &e) && e.Code == "denied"
			}
			if _, err := client.AppDeliveryField(ctx, peer, managerSession, "other", q); !denied(err) {
				t.Fatal("foreign tenant CD query not denied", err)
			}
			d, _ := apps().Delivery("tenant", "app")
			raw, _ := control.ChangeBytes("pause-app-cd", "manager", d.Revision(), control.AppCDChange{Tenant: "tenant", App: "app"})
			var ch control.Change
			_ = json.Unmarshal(raw, &ch)
			op, err := client.Prepare(ctx, peer, managerSession, "manager-pause-cd", ch)
			if err != nil {
				t.Fatal("current CD manager prepare", err)
			}
			accepted, err := client.Operation(ctx, peer, op, false)
			if err != nil || accepted.Result == nil || accepted.Result.Code != state.Applied {
				t.Fatal("current CD manager mutation", accepted, err)
			}
			beforeRevocation := read().Object(control.AppsKey)
			membership, _ := catalog().Membership("tenant", "manager")
			userOp("revoke-cd-manager", "set-membership", membership.Revision, access.Membership{Tenant: "tenant", User: "manager", Role: access.Manager, Enabled: false})
			if _, err := client.AppDeliveryField(ctx, peer, managerSession, "tenant", q); !denied(err) {
				t.Fatal("old session bypassed current CD membership revoke", err)
			}
			d, _ = apps().Delivery("tenant", "app")
			raw, _ = control.ChangeBytes("resume-app-cd", "manager", d.Revision(), control.AppCDChange{Tenant: "tenant", App: "app"})
			_ = json.Unmarshal(raw, &ch)
			op, err = client.Prepare(ctx, peer, managerSession, "revoked-manager-resume-cd", ch)
			if err != nil {
				if !denied(err) {
					t.Fatal("revoked CD manager prepare failed for another reason", err)
				}
			} else {
				rejected, err := client.Operation(ctx, peer, op, false)
				if err != nil && !denied(err) || err == nil && (rejected.Result == nil || rejected.Result.Code != state.Forbidden) {
					t.Fatal("revoked CD manager mutation not denied", rejected, err)
				}
			}
			if read().Object(control.AppsKey) != beforeRevocation {
				t.Fatal("membership revocation/denied CD command rewrote original app")
			}
			if _, err := client.AppDeliveryField(ctx, peer, session, "tenant", q); err != nil {
				t.Fatal("implicit system administrator CD scope", err)
			}
			membership, _ = catalog().Membership("tenant", "manager")
			userOp("restore-cd-manager", "set-membership", membership.Revision, access.Membership{Tenant: "tenant", User: "manager", Role: access.Manager, Enabled: true})
			if _, err := client.AppDeliveryField(ctx, peer, managerSession, "tenant", q); err != nil {
				t.Fatal("explicit current membership restore", err)
			}
			t.Log("actual MYDCP/User/Raft/bbolt CD manager own scope, foreign query denial, current revoke blocks old-session query/new mutation without changing app, implicit admin and explicit current restore; no native facts")
		}
		if err := engine.Snapshot(ctx); err != nil {
			t.Fatal(err)
		}
		return
	}
	// A competing app can be accepted before either one commits space; the
	// actual ordered Goal commit, not acceptance, decides the winner.
	rivalDocument := bytes.Replace(document, []byte("name: app"), []byte("name: rival"), 1)
	rivalPlan, e := client.PlanApp(ctx, peer, session, "tenant", control.AppPlanRequest{Document: rivalDocument})
	if e != nil || rivalPlan.AppPlan == nil {
		t.Fatal("concurrent candidate plan", e)
	}
	userOp("rival-upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: "tenant", App: "rival", Deployment: "rival", ID: "rival-artifact", Length: rivalPlan.AppPlan.Length, Digest: rivalPlan.AppPlan.Digest})
	userOp("rival-part", "put-app-part", 1, control.AppUploadPart{Tenant: "tenant", ID: "rival-artifact", Data: rivalPlan.AppPlan.Data})
	userOp("rival-begin", "begin-app", 0, control.AppBegin{Tenant: "tenant", App: "rival", Deployment: "rival", Upload: "rival-artifact", Operation: "rollout"})
	bridge, task := "", ""
	for _, step := range plan.Steps() {
		if step.Kind == "network-ref" {
			bridge = step.Key
		}
		if step.Kind == "task" {
			task = step.Key
		}
	}
	progress("prepare", task, nil, state.ConditionFailed) // Native dependency has not applied.
	prepared := progress("prepare", bridge, nil, state.Applied)
	stage, _ := execution().Stage(bridge)
	original := *stage.Command
	if policy.AdmitAppMutation(read(), original) {
		t.Fatal("Prepared authorized an effect")
	}
	altered := original
	altered.RequestID = "forged-command"
	altered.Value += " "
	apply(altered, state.Forbidden)
	// A valid signature from a nonmember can neither advance nor add a node actor.
	var forged control.AppProgress
	_ = json.Unmarshal([]byte(prepared.Value), &forged)
	forged.Reporter = admin.Public
	forged.RequestID = "foreign-progress"
	forged.RootRevision = read().Object(control.AppsKey).Revision
	forged.Signature = ed25519.Sign(admin.Private, control.AppProgressBytes(forged))
	forgedCommand, _ := forged.Command()
	apply(forgedCommand, state.Forbidden)
	progress("send", bridge, nil, state.Applied)
	if !policy.AdmitAppMutation(read(), original) {
		t.Fatal("exact Dispatched command denied")
	}
	progress("collect", bridge, nil, state.ConditionFailed) // Missing is not nonexecution.
	progress("unknown", bridge, nil, state.Applied)
	originalRaw, _ := state.EncodeCommand(original)
	missingReply := memberCall("app-result", originalRaw)
	var missing control.AppResult
	if json.Unmarshal(missingReply.Data, &missing) != nil || missing.Found {
		t.Fatal("missing original result was fabricated")
	}
	foreignReply, foreignErr := cluster.CallManagement(ctx, clientMesh, proof, clusterID, peer, cluster.ManagementRequest{Method: "app-result", Latest: true, Input: originalRaw})
	if foreignErr == nil && foreignReply.Code == "ok" {
		t.Fatal("nonmember obtained app result authority")
	}
	stage, _ = execution().Stage(bridge)
	if stage.Journal.Pending == nil || stage.Journal.Pending.Phase != reconcile.RecoveryRequired || *stage.Command != original {
		t.Fatal("Unknown lost original")
	}
	progress("send", bridge, nil, state.ConditionFailed) // No automatic resubmission/reset.
	before := read()
	saved := execution()
	if e = engine.Snapshot(ctx); e != nil {
		t.Fatal(e)
	}
	if e = engine.Close(); e != nil {
		t.Fatal(e)
	}
	engine = nil
	// An established delegated root cannot reopen with this policy silently disabled.
	disabled := options
	disabled.AdmitMutation = nil
	if other, err := cluster.Open(disabled); err == nil {
		_ = other.Close()
		t.Fatal("delegation disabled on existing root")
	}
	_ = mesh.Close()
	mesh, e = mydcp.NewTransport(node, clusterID, lookup)
	if e != nil {
		t.Fatal(e)
	}
	if e = mesh.Listen(peer.Endpoint); e != nil {
		t.Fatal(e)
	}
	open()
	_ = read()
	if read().Index() != before.Index() || !reflect.DeepEqual(saved, execution()) {
		t.Fatal("Snapshot/same DB lost original Unknown")
	}
	// A late original Raft proposal may arrive after Unknown; admission must not
	// confuse that retained exact proposal with permission for a new submission.
	proposal := memberCall("app-command", originalRaw)
	if proposal.Committed == nil || proposal.Committed.Result.Code != state.Applied {
		t.Fatal("late original member command", proposal.Committed)
	}
	committed := proposal.Committed.Result
	actualReply := memberCall("app-result", originalRaw)
	var actual control.AppResult
	if json.Unmarshal(actualReply.Data, &actual) != nil || !actual.Found || actual.Result == nil || *actual.Result != committed {
		t.Fatal("member original result changed")
	}
	if apply(original, state.Applied) != committed {
		t.Fatal("original proposal replay changed result")
	}

	rivalBlueprint, err := deployment.DecodeBlueprint(rivalPlan.AppPlan.Data)
	if err != nil {
		t.Fatal(err)
	}
	rivalReference, rivalTask := "", ""
	for _, step := range rivalBlueprint.Steps() {
		if step.Kind == "network-ref" {
			rivalReference = step.Key
		}
		if step.Kind == "task" {
			rivalTask = step.Key
		}
	}
	progress("prepare", rivalReference, nil, state.Applied, "rival")
	progress("send", rivalReference, nil, state.Applied, "rival")
	rivalExecution, _ := apps().Execution("tenant", "rival")
	rivalStage, _ := rivalExecution.Stage(rivalReference)
	apply(*rivalStage.Command, state.Applied)
	progress("collect", rivalReference, nil, state.Applied, "rival")
	// Registry operations and app goals share one actual admission view. A
	// rejected aggregate leaves both original roots/objects untouched.
	baseResources, err := policy.Resources(read())
	if err != nil {
		t.Fatal(err)
	}
	userOp("manual-overlap-app", "create-tun-network", baseResources.Networks.Revision(), tenancy.TUNDefinition{Tenant: "tenant", Name: "overlap", Members: []tenancy.TUNNode{{Node: peer.ID, Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.86.0.0/24"), Gateway: netip.MustParseAddr("10.86.0.1"), MTU: 1280}}, Addresses: []netip.Prefix{netip.MustParsePrefix("10.99.250.1/32")}}}}, state.ConditionFailed)
	globalLimit, _ := baseResources.Quotas.Limit("", peer.ID)
	globalRevision := globalLimit.Revision
	globalLimit.Revision = 0
	globalLimit.Networks = 0
	userOp("shrink-held-network", "set-node-quota", globalRevision, globalLimit, state.ConditionFailed)
	progress("collect", bridge, nil, state.Applied)
	stage, _ = execution().Stage(bridge)
	if stage.Result == nil || *stage.Result != committed {
		t.Fatal("collector did not use A1 receipt")
	}
	observe := func(key string, sequence uint64, target ...string) deployment.Observation {
		ex := execution()
		digest := plan.Digest()
		if len(target) > 0 {
			ex, _ = apps().Execution("tenant", target[0])
			digest = rivalBlueprint.Digest()
		}
		st, _ := ex.Stage(key)
		o := deployment.Observation{Cluster: clusterID, Plan: digest, Operation: "rollout", Key: key, Native: "fixture-native-" + fmt.Sprint(sequence), Owner: node.Public, Command: state.Digest(*st.Command), Generation: st.Result.Generation, Revision: st.Result.Revision, Sequence: sequence, At: uint64(time.Now().Unix()), Applied: true, Healthy: true}
		o.Signature = ed25519.Sign(node.Private, deployment.ObservationBytes(o))
		return o
	}
	o := observe(bridge, 1)
	bad := o
	bad.Command[0] ^= 1
	bad.Signature = ed25519.Sign(node.Private, deployment.ObservationBytes(bad))
	progress("observe", bridge, &bad, state.ConditionFailed)
	firstReport := progress("observe", bridge, &o, state.Applied)
	rivalObservation := observe(rivalReference, 1, "rival")
	progress("observe", rivalReference, &rivalObservation, state.Applied, "rival")
	if reportMode != "" {
		// New typed reports collect their own superseded receipts in the
		// same actor ledger without erasing other original results.
		native := o.Native
		var latest state.Command
		for sequence := uint64(3); sequence <= 2+2*state.LedgerLimit; sequence++ {
			o = observe(bridge, sequence)
			o.Native = native
			o.Signature = ed25519.Sign(node.Private, deployment.ObservationBytes(o))
			latest = progress("observe", bridge, &o, state.Applied)
		}
		assertReceipts := func() {
			t.Helper()
			s := read()
			if _, known := s.LookupResult(firstReport); known || !s.ModuleExpired(firstReport) {
				t.Fatal("superseded report did not expire")
			}
			if got, known := s.LookupResult(original); !known || got != committed {
				t.Fatal("collection erased original user/native command result")
			}
			latestResult, known := s.LookupResult(latest)
			if !known || apply(latest, state.Applied) != latestResult {
				t.Fatal("lost ACK replay replaced latest original result")
			}
			apply(firstReport, state.Expired)
			if s.ModuleEpoch() != 1 {
				t.Fatal("report collection changed the ledger epoch")
			}
		}
		assertReceipts()
		if err = engine.Snapshot(ctx); err != nil {
			t.Fatal(err)
		}
		if err = engine.Close(); err != nil {
			t.Fatal(err)
		}
		engine = nil
		_ = mesh.Close()
		mesh, err = mydcp.NewTransport(node, clusterID, lookup)
		if err != nil {
			t.Fatal(err)
		}
		if err = mesh.Listen(peer.Endpoint); err != nil {
			t.Fatal(err)
		}
		open()
		assertReceipts()
		t.Log("512 signed member observations through real MYDCP/Raft/bbolt; bounded report collection, exact retained results, old expiry and Snapshot/same DB; native facts are fixtures")
		return
	}
	// Logout revokes new user requests, while the accepted job keeps its frozen
	// scope and still intersects current role/credential/node/image authority.
	originalSession := session
	u, _ := catalog().User("admin")
	userOp("logout-original", "revoke-session", u.Revision, control.SessionRevocation{User: "admin", Session: session.ID})
	progress("prepare", task, nil, state.Applied)
	session, e = client.Login(ctx, peer, "admin", admin.Private)
	if e != nil {
		t.Fatal(e)
	}
	tenant, _ = catalog().Tenant("tenant")
	userOp("untrust", "set-trust", tenant.Revision, control.TrustAssignment{Tenant: "tenant"})
	progress("send", task, nil, state.Forbidden)
	tenant, _ = catalog().Tenant("tenant")
	userOp("trust", "set-trust", tenant.Revision, control.TrustAssignment{Tenant: "tenant", Rules: []access.TrustRule{{Registry: "docker.io", Repository: "**"}}})
	progress("send", task, nil, state.Applied)
	stage, _ = execution().Stage(task)
	taskOriginal := *stage.Command

	taskBase, err := policy.Resources(read())
	if err != nil {
		t.Fatal(err)
	}
	// No task is held until the exact original Goal really commits.
	if used, _ := taskBase.Quotas.Usage("", peer.ID); used != (workload.Resources{}) {
		t.Fatal("base copied app reservation")
	}
	taskResult := apply(taskOriginal, state.Applied)
	// Apps may share the managed network; the first Task commit owns the
	// explicit endpoint. Acceptance/reference commits do not allocate it.
	progress("prepare", rivalTask, nil, state.Applied, "rival")
	progress("send", rivalTask, nil, state.Applied, "rival")
	rivalExecution, _ = apps().Execution("tenant", "rival")
	rivalStage, _ = rivalExecution.Stage(rivalTask)
	rivalRejected := apply(*rivalStage.Command, state.Invalid)
	progress("collect", rivalTask, nil, state.Applied, "rival")
	if read().Object(rivalTask).Present {
		t.Fatal("losing app published the duplicate endpoint")
	}
	if receipt, ok := read().LookupResult(*rivalStage.Command); !ok || receipt != rivalRejected {
		t.Fatal("losing app lost original conflict")
	}
	if _, err = client.PlanApp(ctx, peer, session, "tenant", control.AppPlanRequest{Document: rivalDocument}); err == nil {
		t.Fatal("plan ignored committed endpoint")
	}

	projected, err := policy.ProjectResources(read())
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := projected.Resources.Quotas.Usage("", peer.ID); used != (workload.Resources{CPU: 100000000, Memory: 16 << 20}) || projected.Addresses.Count() != 1 {
		t.Fatal("joint app resource projection", used, projected.Addresses.Count())
	}
	userOp("manual-overflow-app", "reserve-task", taskBase.Quotas.Revision(), tenancy.Reservation{Key: "workload/task/tenant/other/overflow", Tenant: "tenant", Node: peer.ID, Need: workload.Resources{CPU: 950000000, Memory: 16 << 20}}, state.Invalid)
	userOp("manual-duplicate-authority", "reserve-task", taskBase.Quotas.Revision(), tenancy.Reservation{Key: task, Tenant: "tenant", Node: peer.ID, Need: workload.Resources{CPU: 100000000, Memory: 16 << 20}}, state.Invalid)
	// A failed registry candidate cannot leak its synthetic reservation or CAS.
	afterBase, err := policy.Resources(read())
	if err != nil || !reflect.DeepEqual(taskBase, afterBase) {
		t.Fatal("partial manual registry published", err)
	}
	progress("collect", task, nil, state.Applied)
	o = observe(task, 2)
	progress("observe", task, &o, state.Applied)
	progress("finish", "", nil, state.Applied)

	// An unchanged own source can plan again without charging its budget twice.
	samePlan, err := client.PlanApp(ctx, peer, session, "tenant", control.AppPlanRequest{Document: document})
	if err != nil || samePlan.AppPlan == nil {
		t.Fatal("same original reservation credit", err)
	}
	// Native data is retained through node grant revocation, including addresses.
	tenant, _ = catalog().Tenant("tenant")
	userOp("revoke-placement", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant"})
	held, err := policy.ProjectResources(read())
	if err != nil || held.Addresses.Count() != 1 {
		t.Fatal("revoke lost original address", err)
	}
	if used, _ := held.Resources.Quotas.Usage("", peer.ID); used != (workload.Resources{CPU: 100000000, Memory: 16 << 20}) {
		t.Fatal("revoke returned budget", used)
	}
	projectedBefore, e := policy.ProjectResources(read())
	if e != nil {
		t.Fatal(e)
	}
	position := read().Index()
	if e = engine.Snapshot(ctx); e != nil {
		t.Fatal(e)
	}
	if e = engine.Close(); e != nil {
		t.Fatal(e)
	}
	engine = nil
	_ = mesh.Close()
	mesh, e = mydcp.NewTransport(node, clusterID, lookup)
	if e != nil {
		t.Fatal(e)
	}
	if e = mesh.Listen(peer.Endpoint); e != nil {
		t.Fatal(e)
	}
	open()
	_ = read()
	projectedAfter, e := policy.ProjectResources(read())
	if e != nil || !reflect.DeepEqual(projectedBefore, projectedAfter) || read().Index() != position {
		t.Fatal("same DB lost original projected resources", e)
	}
	if execution().Status() != "Succeeded" {
		t.Fatal("metadata witness finish")
	}
	if rights, _, _, ok := read().Principal(original.Actor); !ok || rights != 0 {
		t.Fatal("delegation granted global rights")
	}
	a := apps()
	origin, ok := a.Origin("tenant", "app")
	if !ok || origin.Session.ID != originalSession.ID {
		t.Fatal("original grant replaced")
	}
	encoded, _ := state.Encode(read())
	restored, e := state.Decode(encoded)
	if e != nil {
		t.Fatal(e)
	}
	if e = policy.Validate(restored, restored, state.Command{}); e != nil {
		t.Fatal("restored graph/receipt linkage", e)
	}
	restoredApps, e := policy.Apps(restored)
	ex, ok := restoredApps.Execution("tenant", "app")
	if e != nil || !ok || !reflect.DeepEqual(ex, execution()) {
		t.Fatal("terminal inventory round trip", e)
	}
	if got, ok := restored.LookupResult(taskOriginal); !ok || got != taskResult {
		t.Fatal("terminal original receipt")
	}
	// A hash-valid row without its exact frozen app command/receipt is invalid.
	invalid := taskOriginal
	invalid.RequestID = "forged-new-request"
	invalid.Value = bytes.NewBufferString(taskOriginal.Value + " ").String()
	apply(invalid, state.Forbidden)
	t.Log("actual user/MYDCP -> signed member progress -> reused Execution/A1 exact delegation -> real Raft/bbolt/Unknown Snapshot/same DB/late original receipt -> Inventory claim; owner facts are fixtures, native projector/controller not enabled")
}
