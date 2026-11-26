// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// AppPartBytes is the exact size of every put-app-part chunk except the last.
const AppPartBytes = deployment.ArtifactPartBytes

// REQ-4 (mock) payloads, following the REQUEST.md text. User must be the
// session's own user. The new key's proof of possession is not defined by
// mydcd yet and is not part of the mock payload.
type CredentialAdd struct {
	User       string
	Credential Credential
	Label      string `json:",omitempty"`
}
type CredentialDisable struct {
	User, ID string
}

// NodeSelection is the payload the fake accepts for isolate/restore-node.
type NodeSelection struct {
	Node string
}

func (c *fakeConn) Prepare(ctx context.Context, change Change, rootRevision uint64) (SignedOp, error) {
	return c.prepare(ctx, "", change, rootRevision, nil)
}

// PrepareRequest signs change with a caller-chosen RequestID, as
// userauth.Client.Prepare does; put-certificate needs the receipt's Request.
func (c *fakeConn) PrepareRequest(ctx context.Context, requestID string, change Change, rootRevision uint64) (SignedOp, error) {
	if !validRequestID(requestID) {
		return nil, fail("prepare", CodeInvalid, "request ID")
	}
	return c.prepare(ctx, requestID, change, rootRevision, nil)
}

func (c *fakeConn) prepare(ctx context.Context, requestID string, change Change, rootRevision uint64, reason *control.OperationReason) (SignedOp, error) {
	const m = "prepare"
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, fail(m, CodeTransport, err.Error())
	}
	if c.closed {
		return nil, fail(m, CodeClosed, "")
	}
	if c.session == nil || c.key == nil {
		return nil, fail(m, CodeNotLoggedIn, "")
	}
	if change.Schema == 0 {
		change.Schema = 1
	}
	if change.Principal == "" {
		change.Principal = c.session.User
	}
	if requestID == "" {
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return nil, fail(m, CodeTransport, err.Error())
		}
		requestID = "web-" + hex.EncodeToString(id)
	}
	if err := c.prepareGatewayEvidence(&change, requestID, c.f.now().Unix()); err != nil {
		return nil, err
	}
	op := UserOperation{
		Schema: 1, Session: *c.session, At: c.f.now().Unix(), Epoch: c.f.w.ledgerEpoch,
		RequestID: requestID, RootRevision: rootRevision, Change: change, Reason: reason,
	}
	op.Signature = ed25519.Sign(c.key, control.OperationBytes(op))
	b, err := json.Marshal(op)
	if err != nil {
		return nil, fail(m, CodeInvalid, err.Error())
	}
	return b, nil
}

func (c *fakeConn) decodeOp(m string, raw SignedOp) (UserOperation, [32]byte, error) {
	var op UserOperation
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&op); err != nil {
		return op, [32]byte{}, fail(m, CodeInvalid, "operation")
	}
	if canon, _ := json.Marshal(op); !bytes.Equal(canon, raw) {
		return op, [32]byte{}, fail(m, CodeInvalid, "operation is not canonical")
	}
	if op.Schema != 1 || op.RequestID == "" || !ed25519.Verify(op.Session.Key[:], control.OperationBytes(op), op.Signature) {
		return op, [32]byte{}, fail(m, CodeInvalid, "signature")
	}
	if !ed25519.Verify(c.f.w.issuer.Public().(ed25519.PublicKey), access.SessionBytes(op.Session), op.Session.Signature) {
		return op, [32]byte{}, fail(m, CodeDenied, "session issuer")
	}
	return op, digestOf(raw), nil
}

func (c *fakeConn) Submit(ctx context.Context, raw SignedOp) (Result, error) {
	const m = "submit"
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if err := c.begin(ctx, m, true); err != nil {
		return Result{}, err
	}
	op, digest, err := c.decodeOp(m, raw)
	if err != nil {
		return Result{}, err
	}
	if op.Session.ID != c.session.ID {
		return Result{}, fail(m, CodeDenied, "operation was signed by another session")
	}
	now := c.f.now().Unix()
	if op.At > now || now-op.At > 300 {
		return Result{}, fail(m, CodeExpired, "operation At")
	}
	return c.commit(m, op, digest)
}

func (c *fakeConn) Result(ctx context.Context, raw SignedOp) (Result, bool, error) {
	const m = "result"
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if err := c.begin(ctx, m, true); err != nil {
		return Result{}, false, err
	}
	op, digest, err := c.decodeOp(m, raw)
	if err != nil {
		return Result{}, false, err
	}
	if op.Session.User != c.session.User {
		return Result{}, false, fail(m, CodeDenied, "")
	}
	e, ok := c.f.w.ledger[op.Session.User+"/"+op.RequestID]
	if !ok {
		return Result{}, false, nil
	}
	if e.digest != digest {
		return Result{Code: ResultRequestConflict}, true, nil
	}
	return e.result, true, nil
}

func (c *fakeConn) Resume(ctx context.Context, raw SignedOp) (Result, bool, error) {
	const m = "resume"
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if err := c.begin(ctx, m, true); err != nil {
		return Result{}, false, err
	}
	op, digest, err := c.decodeOp(m, raw)
	if err != nil {
		return Result{}, false, err
	}
	if op.Session.User != c.session.User {
		return Result{}, false, fail(m, CodeDenied, "")
	}
	res, err := c.commit(m, op, digest)
	if err != nil {
		return Result{}, false, err
	}
	return res, true, nil
}

// commit is the shared original-operation path: ledger lookup, CAS, apply,
// optional lost reply. f.mu is held.
func (c *fakeConn) commit(m string, op UserOperation, digest [32]byte) (Result, error) {
	w := c.f.w
	key := op.Session.User + "/" + op.RequestID
	if e, ok := w.ledger[key]; ok {
		if e.digest != digest {
			return Result{Code: ResultRequestConflict}, nil
		}
		return e.result, nil
	}
	if err := c.extensionPreflight(m, op); err != nil {
		return Result{}, err
	}
	lost, applied := c.f.loseReply(m)
	if lost && !applied {
		return Result{}, fail(m, CodeUnknown, "reply lost before commit")
	}
	res, modeled := c.decide(op)
	w.ledger[key] = ledgerEntry{digest: digest, result: res}
	je := JournalEntry{RequestID: op.RequestID, Action: op.Change.Action, User: op.Session.User, Result: res, Modeled: modeled}
	if r := op.Reason; r != nil {
		je.Reason = &OperationReason{Reason: r.Text, Incident: r.IncidentID, ApprovedBy: r.ApprovedBy}
	}
	w.journal = append(w.journal, je)
	if lost {
		return Result{}, fail(m, CodeUnknown, "reply lost after commit")
	}
	return res, nil
}

var (
	errForbidden = errors.New("forbidden")
	errCAS       = errors.New("condition failed")
)

// decide applies the change to the world. It returns the durable result and
// whether the fake modeled the action (false = accepted and recorded only).
func (c *fakeConn) decide(op UserOperation) (Result, bool) {
	w := c.f.w
	actor := op.Session.User
	if u := w.users[actor]; u == nil || !u.rec.Enabled || !w.scopeAllows(actor, op.Change.Action) {
		return Result{Code: ResultForbidden}, true
	}
	key := control.CommandKey(op.Change.Action)
	if !control.UploadCASAllowed(op.Change.Action) && !w.rootAccepted(key, op.RootRevision) {
		return Result{Code: ResultConditionFailed, Index: w.root, Revision: w.keyRoot(key)}, true
	}
	next := w.root + 1
	modeled, err := c.apply(op, actor, next)
	switch {
	case errors.Is(err, errForbidden):
		return Result{Code: ResultForbidden}, true
	case errors.Is(err, errCAS):
		return Result{Code: ResultConditionFailed, Index: w.root, Revision: w.root}, true
	case errors.As(err, new(nodeRemoveRefused)):
		var r nodeRemoveRefused
		errors.As(err, &r)
		return Result{Code: removeResultCodes[r.code], Reason: r.code}, true
	case err != nil:
		return Result{Code: ResultInvalid}, true
	}
	w.root = next
	w.keyRoots[key] = next
	return Result{Code: ResultApplied, Index: next, Revision: next, Generation: 1}, modeled
}

func decodePayload(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (c *fakeConn) apply(op UserOperation, actor string, next uint64) (bool, error) {
	w := c.f.w
	ch := op.Change
	switch ch.Action {
	case ActionPutCertificate, ActionDisableCertificate, ActionDeleteCertificate, ActionSetACMEResponder:
		return true, c.applyRealCertificate(op, actor)
	case ActionVaultRevokeApproval:
		return true, c.applyRevokeApproval(op, actor)
	case ActionSyncApp, ActionRecoverApp, ActionReplanApp, ActionConfigureAppCD, ActionPauseAppCD, ActionResumeAppCD,
		ActionAbandonAppSync, ActionOverrideApp, ActionReleaseOverride:
		return true, c.applyCD(op, actor, next)
	case ActionApproveAppCD, ActionRejectAppCD, ActionGrantCDApprover, ActionDropCDApprover:
		return true, c.applyCDDecision(op, actor, next)
	case ActionVaultInit:
		return true, c.applyVaultInit(op, actor, next)
	case ActionVaultACL, ActionVaultMove, ActionVaultRevoke, ActionVaultRetire, ActionVaultApprovalAge:
		return true, c.applyVaultObject(op, actor, next)
	case ActionSetLifecyclePolicy, ActionPutLifecycleScript, ActionRetireLifecycleScript, ActionDeleteLifecycleScript:
		return true, c.applyLifecycle(op, actor)
	case ActionProposeRoute, ActionApproveRoute, ActionWithdrawRoute:
		return true, c.applyRoute(op, actor, next)
	case ActionDeleteRegistryImage, ActionGCRegistry, ActionPruneRegistryImages:
		return true, c.applyRegistryMaintenance(op, actor)
	case ActionSetIngressHostPolicy:
		return true, c.applyRealIngress(op, actor)
	case ActionIngressBlock, ActionIngressUnblock, ActionIngressBlockExtend:
		return true, c.applyRealIngress(op, actor)
	case ActionSetNodeGateways, ActionSetIngressBalance, ActionDrainIngress, ActionUndrainIngress:
		return true, c.applyIngressOperation(op, actor)
	case ActionPutRegistry, ActionStartRegistry, ActionStopRegistry, ActionDeleteRegistry:
		return true, c.applyRegistry(op, actor)
	case ActionPutVolumeFile, ActionGetVolumeFile, ActionListVolumeFiles, ActionDeleteVolumeFile:
		return true, c.applyRealVolumeFile(op, actor, next)
	case ActionGrantVolumeFiles, ActionRevokeVolumeFileGrant:
		return true, c.applyVolumeGrant(op, actor, next)
	case ActionPutAppLocalServices, ActionClearAppLocalServices:
		return true, c.applyAppLocal(op, actor, next)
	case ActionClearAppLogs:
		return true, c.applyClearAppLogs(op, actor, next)
	case ActionRestartTask:
		return true, c.applyRestartTask(op, actor, next)
	case ActionPutExternalRegistry, ActionDeleteExternalRegistry, ActionBindExternalRegistry, ActionUnbindExternalRegistry:
		return true, c.applyRealExternalRegistry(op, actor)
	case ActionPublishBuildDraft:
		return true, c.applyPublishBuildDraft(op, actor, next)
	case ActionSetImageBuildPolicy, ActionDeleteImageBuildPolicy, ActionBeginImageBuild, ActionCancelImageBuild, ActionDeleteImageBuildJob,
		ActionPutBuildContext, ActionDeleteBuildContext, ActionDeleteBuildVersion, ActionPruneBuildCache:
		return true, c.applyImageBuild(op, actor, next)
	case ActionSetTrust:
		return true, c.applySetTrust(op, actor, next)
	case ActionRaftCompact:
		return true, c.applyRaftCompact(op, actor)
	case ActionBeginBuildZipUpload, ActionPutBuildZipPart, ActionUploadBuildZip, ActionAbortBuildZipUpload:
		return true, c.applyRealZipUpload(op, actor, next)
	case ActionDrainNode, ActionDemoteNode, ActionRotateNodeIdentity, ActionForceRemoveNode:
		if ok, err := c.applyNodeOpsReal(op, actor, next); ok {
			return true, err
		}
		return true, errors.New("payload")
	case ActionCordonNode, ActionUncordonNode, ActionReconnectTunnel, ActionPruneNodeImages:
		return true, c.applyNodeOps(op, actor, next)
	case ActionSetAccountScope:
		return true, c.applyAccountScope(op, actor, next)
	case ActionSetNodeShellPolicy, ActionSetNodeShellNode, ActionSetNodeShellGrant, ActionCloseNodeShell:
		return true, c.applyNodeShell(op, actor)
	case ActionOpenNodeShell:
		return true, c.applyOpenNodeShell(op, actor)
	case ActionCreateTUNNetwork, ActionConfigureNetworkDNS, ActionBeginVolumeCreate, ActionRegisterFixedVolume, ActionVaultCreate:
		return true, c.applySharedCreate(op, actor, next)
	case ActionBeginTenantRetirement, ActionFinishTenantRetirement:
		return true, c.applyTenantRetirement(op, actor, next)
	case ActionPlanNetworkChange, ActionDrainNetwork, ActionCancelNetworkChange, ActionFenceNetworkChange,
		ActionCommitNetworkChange, ActionReconfigureTUN, ActionJoinTUN, ActionLeaveTUN, ActionSetNetworkToggle:
		return true, c.applyNetworkChange(op, actor, next)
	case ActionBeginVolumeMove:
		return true, c.applyVolumeMove(op, actor, next)
	case ActionRotateLedger:
		var v control.LedgerWindow
		if decodePayload(ch.Payload, &v) != nil {
			return true, errors.New("payload")
		}
		if !w.admin(actor) {
			return true, errForbidden
		}
		if ch.Expected != w.ledgerEpoch || v.NextEpoch != w.ledgerEpoch+1 || w.ledgerBusy {
			return true, errCAS
		}
		w.ledgerEpoch = v.NextEpoch
		return true, nil
	case ActionVaultPrepareWrite, ActionVaultDispatchWrite, ActionVaultObserveWrite, ActionVaultPublishWrite:
		return true, c.applyVaultWrite(op, actor, next)
	case ActionStandaloneUp, ActionStandalonePin, ActionStandaloneExtend, ActionStandaloneStop,
		ActionStandaloneStart, ActionStandaloneRestart, ActionStandaloneRemove:
		return true, c.applyStandalone(op, actor, next)
	case ActionCreateTenant:
		var v control.TenantID
		if decodePayload(ch.Payload, &v) != nil || v.ID == "" {
			return true, errors.New("payload")
		}
		if !w.admin(actor) {
			return true, errForbidden
		}
		if _, ok := w.tenants[v.ID]; ok {
			return true, errCAS
		}
		w.tenants[v.ID] = map[string]Role{}
		w.tenantRev[v.ID] = next
		// like access catalog create-tenant: Docker Hub is trusted by default
		w.trust[v.ID] = []TrustRule{{Registry: "docker.io", Repository: "**"}}
		return true, nil

	case ActionSetMembership:
		var v access.Membership
		if decodePayload(ch.Payload, &v) != nil || v.Tenant == "" || v.User == "" {
			return true, errors.New("payload")
		}
		if !w.canManage(actor, v.Tenant) {
			return true, errForbidden
		}
		if w.users[v.User] == nil || v.Enabled && v.Role != RoleManager && v.Role != RoleViewer {
			return true, errors.New("payload")
		}
		if ch.Expected != w.tenantRev[v.Tenant] {
			return true, errCAS
		}
		if v.Enabled {
			w.tenants[v.Tenant][v.User] = v.Role
		} else {
			delete(w.tenants[v.Tenant], v.User)
		}
		w.tenantRev[v.Tenant] = next
		return true, nil

	case ActionSetNodes:
		var v control.NodeAssignment
		if decodePayload(ch.Payload, &v) != nil || v.Tenant == "" {
			return true, errors.New("payload")
		}
		if !w.admin(actor) {
			return true, errForbidden
		}
		if _, ok := w.tenants[v.Tenant]; !ok || ch.Expected != w.tenantRev[v.Tenant] {
			return true, errCAS
		}
		for _, n := range v.Nodes {
			if !w.knownNode(n) {
				return true, errors.New("unknown node " + n)
			}
		}
		w.tenantNodes[v.Tenant] = append([]string(nil), v.Nodes...)
		w.tenantRev[v.Tenant] = next
		return true, nil

	case ActionPutUser:
		var v access.User
		if decodePayload(ch.Payload, &v) != nil || v.ID == "" || v.Username == "" {
			return true, errors.New("payload")
		}
		if !w.admin(actor) {
			return true, errForbidden
		}
		if v.AutomationOnly && slices.ContainsFunc(v.Credentials, func(cr Credential) bool { return cr.Enabled && cr.Method != MethodPrivateKey }) {
			return true, errors.New("key-only account")
		}
		old := w.users[v.ID]
		if old == nil && ch.Expected != 0 || old != nil && old.rec.Revision != ch.Expected {
			return true, errCAS
		}
		v.Revision = next
		u := &fakeUser{rec: cloneUser(v)}
		if old != nil {
			u.secret = old.secret
		}
		w.users[v.ID] = u
		return true, nil

	case ActionRevokeSession:
		var v control.SessionRevocation
		if decodePayload(ch.Payload, &v) != nil || v.User == "" || v.Session == "" {
			return true, errors.New("payload")
		}
		if v.User != actor && !w.admin(actor) {
			return true, errForbidden
		}
		w.revoked[v.User+"/"+v.Session] = true
		return true, nil

	case ActionSetNodeCLIPolicy:
		var v struct {
			DisableNodeCLIOperation bool `json:"disable_node_cli_operation"`
		}
		if decodePayload(ch.Payload, &v) != nil {
			return true, errors.New("payload")
		}
		if !w.admin(actor) {
			return true, errForbidden
		}
		if ch.Expected != w.nodeCLI.Revision {
			return true, errCAS
		}
		w.nodeCLI = NodeCLIPolicy{Revision: next, DisableNodeCLIOperation: v.DisableNodeCLIOperation}
		return true, nil

	case ActionIsolateNode, ActionRestoreNode, ActionRemoveNode:
		return true, c.applyNodeLifecycle(op, actor, next)

	case ActionBeginAppUpload:
		var v control.AppUploadBegin
		if decodePayload(ch.Payload, &v) != nil || v.Tenant == "" || v.App == "" || v.ID == "" || v.Length <= 0 || v.Length > 4<<20 {
			return true, errors.New("payload")
		}
		if !w.canManage(actor, v.Tenant) {
			return true, errForbidden
		}
		key := v.Tenant + "/" + v.ID
		if w.uploads[key] != nil || ch.Expected != 0 {
			return true, errCAS
		}
		w.uploads[key] = &upload{tenant: v.Tenant, user: actor, parts: map[int][]byte{},
			view: AppUploadView{ID: v.ID, App: v.App, Deployment: v.Deployment, Revision: 1, Length: v.Length, Digest: v.Digest}}
		return true, nil

	case ActionPutAppPart:
		var v control.AppUploadPart
		if decodePayload(ch.Payload, &v) != nil {
			return true, errors.New("payload")
		}
		u := w.uploads[v.Tenant+"/"+v.ID]
		if u == nil {
			return true, errors.New("unknown upload")
		}
		if u.user != actor || !w.canManage(actor, v.Tenant) {
			return true, errForbidden
		}
		if ch.Expected != u.view.Revision {
			return true, errCAS
		}
		n := u.partCount()
		if v.Index < 0 || v.Index >= n || len(v.Data) != min(AppPartBytes, u.view.Length-v.Index*AppPartBytes) {
			return true, errors.New("part")
		}
		if old, ok := u.parts[v.Index]; ok && !bytes.Equal(old, v.Data) {
			return true, errors.New("part conflict")
		}
		u.parts[v.Index] = bytes.Clone(v.Data)
		if len(u.missing()) == 0 && digestOf(u.document()) != u.view.Digest {
			delete(u.parts, v.Index)
			return true, errors.New("digest")
		}
		u.view.Revision++
		return true, nil

	case ActionAbortAppUpload:
		var v control.AppUploadSelection
		if decodePayload(ch.Payload, &v) != nil {
			return true, errors.New("payload")
		}
		u := w.uploads[v.Tenant+"/"+v.ID]
		if u == nil {
			return true, errors.New("unknown upload")
		}
		if u.user != actor && !w.canManage(actor, v.Tenant) {
			return true, errForbidden
		}
		delete(w.uploads, v.Tenant+"/"+v.ID)
		return true, nil

	case ActionBeginApp:
		var v control.AppBegin
		if decodePayload(ch.Payload, &v) != nil || v.Tenant == "" || v.App == "" || v.Upload == "" || v.Operation == "" {
			return true, errors.New("payload")
		}
		if !w.canManage(actor, v.Tenant) {
			return true, errForbidden
		}
		u := w.uploads[v.Tenant+"/"+v.Upload]
		if u == nil || len(u.missing()) != 0 || u.view.App != v.App {
			return true, errors.New("upload incomplete")
		}
		if a := w.apps[v.Tenant+"/"+v.App]; a != nil && !a.view.Retiring && a.view.Revision != ch.Expected {
			return true, errCAS
		}
		if len(w.missingApprovals(op)) > 0 {
			return true, errors.New("group approval required")
		}
		saved := w.root
		w.root = next
		_, err := w.deploy(v.Tenant, v.App, u.document(), w.users[actor].rec.Username, v.Operation, c.f.now().Unix())
		w.root = saved
		if err != nil {
			return true, err
		}
		delete(w.uploads, v.Tenant+"/"+v.Upload)
		return true, nil

	case ActionDownApp:
		var v control.AppDown
		if decodePayload(ch.Payload, &v) != nil || v.Tenant == "" || v.App == "" || v.Operation == "" {
			return true, errors.New("payload")
		}
		if !w.canManage(actor, v.Tenant) {
			return true, errForbidden
		}
		a := w.apps[v.Tenant+"/"+v.App]
		if a == nil || a.view.Retiring {
			return true, errors.New("unknown app")
		}
		if ch.Expected != a.view.Revision {
			return true, errCAS
		}
		now := c.f.now().Unix()
		a.view.Retiring, a.view.Revision, a.view.Health = true, next, ""
		a.view.Operation = OperationSummary{ID: v.Operation, Status: "succeeded", CompletedAt: uint64(now), Submitter: w.users[actor].rec.Username, Epoch: 1}
		a.ops[v.Operation] = &AppOperation{Tenant: v.Tenant, App: v.App, ID: v.Operation, Status: "succeeded", Submitter: w.users[actor].rec.Username, StartedAt: now, CompletedAt: now, Steps: []string{"stop", "release"}}
		a.tasks = nil
		return true, nil

	case ActionAddCredential:
		var v CredentialAdd
		if decodePayload(ch.Payload, &v) != nil || v.User != actor || v.Credential.ID == "" || v.Credential.Method != MethodPrivateKey || v.Credential.PublicKey == ([32]byte{}) {
			return true, errors.New("payload")
		}
		u := w.users[actor]
		if ch.Expected != u.rec.Revision {
			return true, errCAS
		}
		for _, cr := range u.rec.Credentials {
			if cr.ID == v.Credential.ID || cr.Method == MethodPrivateKey && cr.PublicKey == v.Credential.PublicKey {
				return true, errors.New("duplicate credential")
			}
		}
		v.Credential.Enabled = true
		v.Credential.VerifierRef = ""
		u.rec.Credentials = append(u.rec.Credentials, v.Credential)
		u.rec.Revision = next
		return true, nil

	case ActionDisableCredential:
		var v CredentialDisable
		if decodePayload(ch.Payload, &v) != nil || v.User != actor || v.ID == "" {
			return true, errors.New("payload")
		}
		u := w.users[actor]
		if ch.Expected != u.rec.Revision {
			return true, errCAS
		}
		enabled := 0
		for _, cr := range u.rec.Credentials {
			if cr.Enabled {
				enabled++
			}
		}
		for i := range u.rec.Credentials {
			if u.rec.Credentials[i].ID == v.ID {
				if u.rec.Credentials[i].Enabled && enabled == 1 {
					return true, errors.New("last credential")
				}
				u.rec.Credentials[i].Enabled = false
				u.rec.Revision = next
				return true, nil
			}
		}
		return true, errors.New("unknown credential")
	}
	// Not modeled: accepted and journaled so screens can exercise the
	// operation panel, but no fake state changes.
	return false, nil
}

func (u *upload) partCount() int { return (u.view.Length + AppPartBytes - 1) / AppPartBytes }

func (u *upload) missing() []int {
	var out []int
	for i := 0; i < u.partCount(); i++ {
		if _, ok := u.parts[i]; !ok {
			out = append(out, i)
		}
	}
	return out
}

func (u *upload) document() []byte {
	var b []byte
	for i := 0; i < u.partCount(); i++ {
		b = append(b, u.parts[i]...)
	}
	return b
}
