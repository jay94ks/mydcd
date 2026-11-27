// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/credentials"
	"github.com/jay94ks/seafield/internal/deployment"
)

// UserOperation is immutable across transmission, relay and result recovery.
// At is checked against the edge clock BEFORE admission. Committed replay uses
// this fixed input while rechecking current account/roles/credential policy.
type UserOperation struct {
	Schema       uint8
	Session      access.Session
	At           int64
	Epoch        uint64
	RequestID    string
	RootRevision uint64
	Change       Change
	Signature    []byte
	Reason       *OperationReason `json:",omitempty"`
}

// UploadCASAllowed identifies metadata-only artifact mutations with their own
// exact upload revision. App acceptance and native/resource commands cannot
// use this mode; app acceptance has its own optional signed intent target.
func UploadCASAllowed(action string) bool {
	return action == "begin-app-upload" || action == "put-app-part" || action == "abort-app-upload" || action == "put-build-zip-part" || action == "abort-build-zip-upload" || action == "upload-build-zip"
}

func AppDownCASAllowed(change Change) bool {
	var down AppDown
	return change.Action == "down-app" && change.Expected > 0 && canonical(change.Payload, &down) == nil && down.Tenant != "" && down.App != "" && down.Operation != "" && down.Target != nil && *down.Target != ([32]byte{})
}

func AppFieldCASAllowed(change Change) bool {
	var q AppOverrideChange
	return (change.Action == "override-app" || change.Action == "release-app-override") && change.Expected > 0 && canonical(change.Payload, &q) == nil && q.Target != nil && *q.Target != ([32]byte{}) && q.Tenant != "" && q.App != "" && deployment.AllowedAppOverride(q.Path)
}

func OperationBytes(op UserOperation) []byte {
	op.Signature = nil
	b, _ := json.Marshal(op)
	return append([]byte("sfc-user-operation-1\x00"), b...)
}

// VerifyOriginal proves immutable ownership without asserting current account
// authority. Only result lookup may use this alone, after authenticating the
// CURRENT session of the SAME stable user. It can never authorize an effect.
func (op UserOperation) VerifyOriginal(cluster [32]byte) error {
	if op.Reason != nil && !op.Reason.Valid() {
		return access.ErrDenied
	}
	if op.Schema != 1 || op.Epoch == 0 || op.RequestID == "" || op.Change.Schema != 1 || op.Change.Action == "enroll" || op.Change.Principal != op.Session.User || op.Session.Schema != 1 || op.Session.User == "" || cluster == ([32]byte{}) || op.Session.Cluster != cluster || op.Session.Key == ([32]byte{}) || op.Session.Issuer == ([32]byte{}) || op.Session.IssuedAt < 0 || op.At < op.Session.IssuedAt || op.At >= op.Session.ExpiresAt || op.Session.ExpiresAt-op.Session.IssuedAt > access.MaxSessionSeconds || !ed25519.Verify(ed25519.PublicKey(op.Session.Issuer[:]), access.SessionBytes(op.Session), op.Session.Signature) || !ed25519.Verify(ed25519.PublicKey(op.Session.Key[:]), OperationBytes(op), op.Signature) {
		return access.ErrDenied
	}
	_, err := op.Command()
	return err
}

func (op UserOperation) Command() (state.Command, error) {
	if op.Reason != nil && !op.Reason.Valid() {
		return state.Command{}, access.ErrInvalid
	}
	if op.Change.Action == "standalone-extend" && !StandaloneCASAllowed(op.Change) {
		return state.Command{}, access.ErrDenied
	}
	if !StandaloneCASAllowed(op.Change) && (op.Change.Action == "standalone-pin" || op.Change.Action == "standalone-remove") {
		var q StandaloneChange
		if canonical(op.Change.Payload, &q) == nil && q.Target != nil {
			return state.Command{}, access.ErrDenied
		}
	}
	if !StandaloneCASAllowed(op.Change) && standaloneControlAction(op.Change.Action) != "" {
		var q TaskRestartChange
		if canonical(op.Change.Payload, &q) == nil && q.ManagementTarget != nil {
			return state.Command{}, access.ErrDenied
		}
	}
	if !AppFieldCASAllowed(op.Change) && (op.Change.Action == "override-app" || op.Change.Action == "release-app-override") {
		var q AppOverrideChange
		if canonical(op.Change.Payload, &q) != nil || q.Target != nil {
			return state.Command{}, access.ErrDenied
		}
	}
	if op.Change.Action == "down-app" && !AppDownCASAllowed(op.Change) {
		var down AppDown
		if canonical(op.Change.Payload, &down) != nil || down.Target != nil {
			return state.Command{}, access.ErrDenied
		}
	}
	switch op.Change.Action {
	case "begin-app":
		var q AppBegin
		if canonical(op.Change.Payload, &q) != nil || q.Target != nil && !AppBeginCASAllowed(op.Change) {
			return state.Command{}, access.ErrDenied
		}
	case "put-app-local-services", "clear-app-local-services":
		var q AppLocalChange
		if canonical(op.Change.Payload, &q) != nil || !q.valid(op.Change.Action) || op.Change.Expected == 0 {
			return state.Command{}, access.ErrDenied
		}
	case "sync-app", "recover-app", "replan-app", "configure-app-cd", "pause-app-cd", "resume-app-cd", "abandon-app-sync":
		var q AppCDChange
		if canonical(op.Change.Payload, &q) != nil || q.Target != nil && !AppCDTargetCASAllowed(op.Change) {
			return state.Command{}, access.ErrDenied
		}
	}
	b, err := json.Marshal(op)
	if err != nil {
		return state.Command{}, err
	}
	c := state.Command{Kind: state.Module, Actor: "user/" + hex.EncodeToString(op.Session.Key[:]), Epoch: op.Epoch, RequestID: op.RequestID, Key: CommandKey(op.Change.Action), Expected: op.RootRevision, Value: string(b)}
	if c.Key == StorageKey {
		c.Kind = state.ModuleWindow
	}
	if UploadCASAllowed(op.Change.Action) {
		c.Kind = state.ModuleUpload
	}
	if AppDownCASAllowed(op.Change) {
		c.Kind = state.ModuleAppDown
	}
	if AppFieldCASAllowed(op.Change) {
		c.Kind = state.ModuleAppCAS
	}
	if StandaloneCASAllowed(op.Change) {
		c.Kind = state.ModuleAppCAS
	}
	if AppBeginCASAllowed(op.Change) || AppLocalCASAllowed(op.Change) || AppCDDecisionCASAllowed(op.Change) || AppCDTargetCASAllowed(op.Change) || AppLogClearCASAllowed(op.Change) || TaskRestartCASAllowed(op.Change) {
		if UploadCASAllowed(op.Change.Action) || AppDownCASAllowed(op.Change) || AppFieldCASAllowed(op.Change) || StandaloneCASAllowed(op.Change) && standaloneControlAction(op.Change.Action) == "" {
			return state.Command{}, access.ErrDenied
		}
		c.Kind = state.ModuleAppCAS
	}
	if _, err := state.EncodeCommand(c); err != nil {
		return state.Command{}, err
	}
	return c, nil
}

func (p Policy) Issuer(key [32]byte) access.Issuer {
	issuer := access.Issuer{Key: key, Epoch: 1}
	for _, current := range p.Issuers {
		issuer.Enabled = issuer.Enabled || current != ([32]byte{}) && current == key
	}
	return issuer
}

func selfLogout(op UserOperation) bool {
	var target SessionRevocation
	return op.Change.Action == "revoke-session" && canonical(op.Change.Payload, &target) == nil && target.User == op.Session.User && target.Session == op.Session.ID
}

func (op UserOperation) SelfLogout() bool { return selfLogout(op) }

// Operation verifies the ORIGINAL signed command, including its CAS and ledger
// identity. receiptOnly permits only the exact self-logout proof after session
// revocation; it never authorizes an effect or a general catalog read.
func (p Policy) Operation(c access.Catalog, command state.Command, receiptOnly bool) (UserOperation, error) {
	var op UserOperation
	if canonical([]byte(command.Value), &op) != nil || op.VerifyOriginal(p.Cluster) != nil {
		return op, access.ErrDenied
	}
	want, err := op.Command()
	if err != nil || want != command || !ed25519.Verify(ed25519.PublicKey(op.Session.Key[:]), OperationBytes(op), op.Signature) {
		return op, access.ErrDenied
	}
	if receiptOnly && selfLogout(op) {
		err = c.VerifyLogoutReceipt(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At)
	} else {
		err = c.VerifySession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At)
	}
	return op, err
}

func (p Policy) AdmitModule(s state.State, command state.Command) bool {
	current, err := p.Current(s)
	if err != nil {
		return false
	}
	p = current
	if book, ok := bookFor(command.Key); ok && book.AdmitReport != nil && strings.HasPrefix(command.Actor, "node/") && (!book.ReportOnly || command.Kind == state.ModuleReport) {
		return book.AdmitReport(p, s, command) == nil
	}
	if command.Key == CredentialsKey && command.Kind == state.ModuleReport && strings.HasPrefix(command.Actor, "node/") {
		_, err := p.credentialStoreReport(s, command)
		return err == nil
	}
	if command.Key == CertificatesKey && command.Kind == state.ModuleReport && strings.HasPrefix(command.Actor, "node/") {
		_, err := p.certificateExpiry(s, command)
		return err == nil
	}
	if command.Key == ImageBuildKey && command.Kind == state.ModuleReport && strings.HasPrefix(command.Actor, "node/") {
		if _, _, err := p.imageBuildCacheAutomaticReport(s, command); err == nil {
			return true
		}
		if _, _, err := p.imageBuildAutomaticGitReport(s, command); err == nil {
			return true
		}
		if _, _, err := p.imageBuildGitObservationReport(s, command); err == nil {
			return true
		}
		if _, _, err := p.imageBuildCachePruneReport(s, command); err == nil {
			return true
		}
		if _, _, err := p.imageBuildJobReport(s, command); err == nil {
			return true
		}
		_, _, err := p.imageBuildOwnerReport(s, command)
		return err == nil
	}
	if command.Key == ExternalRegistriesKey && strings.HasPrefix(command.Actor, "node/") {
		_, err := p.externalRegistryCloseReport(s, command)
		return err == nil
	}
	if command.Key == CatalogKey && command.Kind == state.ModuleReport && strings.HasPrefix(command.Actor, "node/") {
		var report TenantRetirementReport
		if canonical([]byte(command.Value), &report) != nil {
			return false
		}
		resolved, err := p.ResolveTenantRetirementReport(s, report.Proof.Owner, []byte(command.Value))
		return err == nil && resolved == command
	}
	if command.Key == RegistryMaintenanceKey && strings.HasPrefix(command.Actor, "node/") {
		_, err := p.registryMaintenanceReport(s, command)
		return err == nil
	}
	if command.Key == ResourcesKey && strings.HasPrefix(command.Actor, "node/") && bridgeClosedValue(command.Value) {
		_, err := p.bridgeClosedReport(s, command)
		return err == nil
	}
	if command.Key == ResourcesKey && strings.HasPrefix(command.Actor, "node/") {
		_, err := p.systemNetworkReport(s, command)
		return err == nil
	}
	if command.Key == RegistriesKey && strings.HasPrefix(command.Actor, "node/") {
		_, err := p.registryReport(s, command)
		return err == nil
	}
	if command.Key == LifecycleKey && strings.HasPrefix(command.Actor, "node/") {
		_, err := p.checkerBuildReport(s, command)
		return err == nil
	}
	if command.Key == NodeStorageKey && strings.HasPrefix(command.Actor, "node/") {
		_, _, err := p.nodeStorageReport(s, command)
		return err == nil
	}
	if command.Key == VolumesKey && strings.HasPrefix(command.Actor, "node/") {
		if volumeFileReportValue([]byte(command.Value)) {
			_, err := p.volumeFileReport(s, command)
			return err == nil
		}
		if volumeMoveReportValue([]byte(command.Value)) {
			_, err := p.volumeMoveReport(s, command)
			return err == nil
		}
		if volumeCreateReportValue([]byte(command.Value)) {
			_, err := p.volumeCreateReport(s, command)
			return err == nil
		}
		if volumeDeleteReportValue([]byte(command.Value)) {
			_, err := p.volumeDeleteReport(s, command)
			return err == nil
		}
		if restoreReportValue([]byte(command.Value)) {
			_, err := p.restoreReport(s, command)
			return err == nil
		}
		_, err := p.backupReport(s, command)
		return err == nil
	}
	if command.Key == VaultKey && command.Kind == state.ModuleReport && strings.HasPrefix(command.Actor, "node/") {
		_, err := p.vaultHolderReport(s, command)
		return err == nil
	}
	if command.Key == VaultKey && strings.HasPrefix(command.Actor, "node/") {
		_, err := p.vaultApprovalReport(s, command)
		return err == nil
	}
	if command.Key == AppsKey && strings.HasPrefix(command.Actor, "node/") {
		if standalonePolicyValue([]byte(command.Value)) {
			_, err := p.standalonePolicyReport(s, command)
			return err == nil
		}
		if taskRestartReportValue([]byte(command.Value)) {
			_, err := p.taskRestartReport(s, command)
			return err == nil
		}
		if appDeliveryReportValue([]byte(command.Value)) {
			_, err := p.appDeliveryProgress(s, command)
			return err == nil
		}
		if routeRetirementReportValue([]byte(command.Value)) {
			_, err := p.routeRetirementReport(s, command)
			return err == nil
		}
		if routeDispatchReportValue([]byte(command.Value)) {
			_, err := p.routeDispatchReport(s, command)
			return err == nil
		}
		if networkDNSReportValue([]byte(command.Value)) {
			_, err := p.networkDNSProgress(s, command)
			return err == nil
		}
		_, err := p.appProgress(s, command)
		return err == nil
	}
	if command.Key == MembersKey && strings.HasPrefix(command.Actor, "node/") {
		_, err := p.memberReport(s, command)
		return err == nil
	}
	c, err := p.Catalog(s)
	if err != nil {
		return false
	}
	_, err = p.Operation(c, command, false)
	return err == nil
}

// AuthorizeResume adds the CURRENT owner's session ceiling to the unchanged
// original operation. The FSM still verifies the original grant and current
// policy; re-login never bypasses old credential revocation or rewrites CAS.
func (p Policy) AuthorizeResume(s state.State, c access.Catalog, op UserOperation, current access.Session, now int64) error {
	if current.User != op.Session.User || c.VerifySession(current, p.Cluster, p.Issuer(current.Issuer), now) != nil {
		return access.ErrDenied
	}
	if op.SelfLogout() {
		return nil
	}
	op.Session, op.At = current, now
	return p.authorizeChange(s, c, op)
}

func (p Policy) authorizeChange(s state.State, c access.Catalog, op UserOperation) error {
	book, booked := actionBook(op.Change.Action)
	if booked && book.Authorize != nil && book.OwnScope {
		return book.Authorize(p, s, c, op)
	}
	if CommandKey(op.Change.Action) == ImageBuildKey {
		return p.authorizeImageBuild(c, op)
	}
	if !selfLogout(op) && c.OperationAllowed(op.Session, op.Change.Action) != nil {
		return access.ErrDenied
	}
	if booked && book.Authorize != nil {
		return book.Authorize(p, s, c, op)
	}
	if CommandKey(op.Change.Action) == CertificatesKey {
		return p.authorizeCertificate(c, op)
	}
	if CommandKey(op.Change.Action) == IngressManagementKey {
		return p.ingressBlockAuthorized(s, c, op)
	}
	if op.Change.Action == "set-node-cli-policy" {
		independent, err := p.nodeKeyContext(s, c)
		if err != nil || independent.VerifyManagementApproval(op.Session) != nil {
			return access.ErrDenied
		}
		return independent.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "")
	}
	if CommandKey(op.Change.Action) == RegistryMaintenanceKey {
		return p.authorizeRegistryMaintenance(c, op)
	}
	if CommandKey(op.Change.Action) == ExternalRegistriesKey {
		return p.authorizeExternalRegistry(c, op)
	}
	if CommandKey(op.Change.Action) == RegistriesKey {
		return p.authorizeRegistry(c, op)
	}
	if CommandKey(op.Change.Action) == LifecycleKey {
		return p.authorizeLifecycle(c, op)
	}
	if CommandKey(op.Change.Action) == NodeStorageKey {
		return p.authorizeNodeStorage(c, op)
	}
	if CommandKey(op.Change.Action) == VaultKey {
		return p.authorizeVault(s, c, op)
	}
	if CommandKey(op.Change.Action) == AppsKey {
		return p.authorizeApp(c, op)
	}
	if CommandKey(op.Change.Action) == VolumesKey {
		return p.authorizeVolume(c, op)
	}
	if CommandKey(op.Change.Action) == ResourcesKey {
		return p.authorizeResource(s, c, op)
	}
	issuer := p.Issuer(op.Session.Issuer)
	action, tenant := access.ManageCluster, ""
	switch op.Change.Action {
	case "volume-file-grant", "volume-file-revoke":
		var v access.VolumeFileFolderGrant
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		return c.AuthorizeSession(op.Session, p.Cluster, issuer, op.At, v.Tenant, access.ManageVolumes, "")
	case "add-credential":
		// The account's own key (with its proof), or a system administrator
		// changing any account, its own too, without a proof.
		var v access.CredentialAddition
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		if v.User == op.Session.User && (v.Proof != nil || !c.SystemAllowed(v.User)) {
			return c.AuthorizeCredentialManagement(op.Session, p.Cluster, issuer, op.At, v.User)
		}
	case "disable-credential":
		var v access.CredentialDisable
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		if v.User == op.Session.User {
			if err := c.AuthorizeCredentialManagement(op.Session, p.Cluster, issuer, op.At, v.User); err == nil || !c.SystemAllowed(v.User) {
				return err
			}
		}
	case "issue-initial-credential":
		var fact credentials.InitialFact
		if canonical(op.Change.Payload, &fact) != nil || !fact.Verify() || op.Change.Expected != fact.Request.ExpectedUserRevision {
			return access.ErrInvalid
		}
		return p.InitialCredentialAllowed(s, op.Session, op.At, fact.Request)
	case "put-user", "set-account-scope", "create-tenant", "begin-tenant-retirement", "finish-tenant-retirement", "set-nodes", "rotate-node-identity", "set-node-endpoint", "drain-node", "cordon-node", "uncordon-node", "invite-node", "cancel-node-invite", "abort-node-join", "promote-node", "demote-node", "rotate-ledger", "isolate-node", "restore-node", "remove-node", "force-remove-node", "resume-node-operation", "rotate-node-operations":
	case "set-membership":
		var v access.Membership
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		action, tenant = access.ManageMembers, v.Tenant
	case "set-trust":
		var v TrustChange
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		action, tenant = access.ManageTrust, v.Tenant
	case "revoke-session":
		if selfLogout(op) {
			return nil
		}
	default:
		return access.ErrInvalid
	}
	return c.AuthorizeSession(op.Session, p.Cluster, issuer, op.At, tenant, action, "")
}
