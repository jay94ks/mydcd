// SPDX-License-Identifier: Apache-2.0

// Package control joins reusable policy cores to the committed FSM metadata.
// It has no clocks, credentials, network, native effects or separate database.
package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

const CatalogKey = "control/access"
const catalogPartSize = 32 << 10

var ErrCatalog = errors.New("invalid committed control catalog")

// invariantFailure is ErrCatalog with a fixed name for the invariant it broke,
// so ValidateStage can say which one. It never carries state or input text.
type invariantFailure string

func (r invariantFailure) Error() string        { return ErrCatalog.Error() }
func (r invariantFailure) Is(target error) bool { return target == ErrCatalog }

type Policy struct {
	Cluster, BootstrapKey [32]byte
	Issuers               [][32]byte
	TrustRoot             [32]byte
	Genesis               config.Peer
}

// ID binds the activated checkpoint/reducer policy into the engine's root
// identity. A restart cannot silently disable the reducer or change its anchor.
func (p Policy) ID() [32]byte {
	b := append([]byte("mydc-access-catalog-policy-1\x00"), p.Cluster[:]...)
	b = append(b, p.BootstrapKey[:]...)

	b = append(b, []byte("/managed-root-1/")...)
	return sha256.Sum256(append(b, p.TrustRoot[:]...))
}

// Change.Principal is only a selection hint. Reduce requires the authenticated
// full-key Command.Actor to match that current user's enabled private key. The
// user session/password/token adapter is a separate admission boundary.
type Change struct {
	Schema    uint8
	Action    string
	Principal string
	Expected  uint64
	Payload   json.RawMessage
}

type TenantID struct{ ID string }
type NodeAssignment struct {
	Tenant string
	Nodes  []string
}
type TrustAssignment struct {
	Tenant string
	Rules  []access.TrustRule
}
type SessionRevocation struct{ User, Session string }

func ChangeBytes(action, principal string, expected uint64, payload any) ([]byte, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Change{1, action, principal, expected, b})
}

func canonical(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return ErrCatalog
	}
	b, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, b) {
		return ErrCatalog
	}
	return nil
}

// Catalog verifies the complete checkpoint, then consumes the same access core
// as the early mocks. An absent root is a blank, unconsumed bootstrap anchor.
func (p Policy) Catalog(s state.State) (access.Catalog, error) {
	raw, revision, err := readCheckpoint(s, CatalogKey, p.Cluster, p.BootstrapKey)
	if err != nil {
		return access.Catalog{}, err
	}
	if raw == nil {
		return access.New(p.BootstrapKey)
	}
	c, err := access.Decode(raw)
	if err != nil || c.Revision() != revision {
		return access.Catalog{}, ErrCatalog
	}
	if c.NodeCLI().DisableNodeCLIOperation {
		c, err = p.nodeKeyContext(s, c)
		if err != nil || c.ValidateNodeCLI() != nil {
			return access.Catalog{}, ErrCatalog
		}
	}
	return c, nil
}
func (p Policy) Validate(before, after state.State, command state.Command) error {
	_, err := p.validateStage(before, after, command)
	return err
}

// ValidateStage is Validate that also names the first check that refuses
// after, or "" when it passes. Local diagnostics only; same verdict.
func (p Policy) ValidateStage(before, after state.State, command state.Command) (string, error) {
	stage, err := p.validateStage(before, after, command)
	var reason invariantFailure
	if errors.As(err, &reason) {
		stage += "/" + string(reason)
	}
	return stage, err
}

func (p Policy) validateStage(before, after state.State, command state.Command) (string, error) {
	if _, err := p.NodeShells(after); err != nil {
		return "node-shells", err
	}
	if _, err := p.Certificates(after); err != nil {
		return "certificates", err
	}
	if _, err := p.IngressManagement(after); err != nil {
		return "ingress", err
	}
	if err := p.validateImageBuildState(before, after); err != nil {
		return "image-builds", err
	}
	if _, err := p.RegistryMaintenanceJobs(after); err != nil {
		return "registry-maintenance", err
	}
	if _, err := p.ImageCacheJobs(after); err != nil {
		return "image-cache", err
	}
	if _, err := p.TunnelReconnections(after); err != nil {
		return "tunnels", err
	}
	if _, err := p.Compactions(after); err != nil {
		return "compactions", err
	}
	if _, err := p.Catalog(after); err != nil {
		return "catalog", err
	}
	if err := p.validateTenantRetirements(after); err != nil {
		return "tenant-retirements", err
	}
	if _, err := p.Members(after); err != nil {
		return "members", err
	}
	resources, err := p.Resources(after)
	if err != nil {
		return "resources", err
	}
	volumes, err := p.Volumes(after)
	if err != nil {
		return "volumes", err
	}
	registries, err := p.Registries(after)
	if err != nil {
		return "registries", err
	}
	if _, err := p.ExternalRegistries(after); err != nil {
		return "external-registries", err
	}
	if err = p.validateRegistryRefs(registries, volumes, resources); err != nil {
		return "registry-refs", err
	}
	roots, err := p.NodeStorage(after)
	if err != nil {
		return "node-storage", err
	}
	if err = p.validateFixedVolumes(roots, volumes); err != nil {
		return "fixed-volumes", err
	}
	vault, err := p.Vault(after)
	if err != nil {
		return "vault", err
	}
	apps, err := p.readOnlyApps(after)
	if err != nil {
		return "apps", err
	}
	// These views all belong to this exact immutable candidate. Reusing
	// their checked decodes avoids reparsing every app history for each
	// invariant without caching across states or skipping any check.
	projection, err := p.projectResources(after, resources, apps, volumes)
	if err != nil {
		return "resource-projection", err
	}
	if err := p.validateAppCommands(after, apps, command); err != nil {
		return "app-commands", err
	}
	if err := p.validateManagedTaskDNS(after, projection, command); err != nil {
		return "task-dns", err
	}
	checkers, checkerErr := p.Lifecycles(after)
	if checkerErr != nil || validateCheckerBindings(apps, checkers) != nil {
		return "checkers", ErrCatalog
	}
	if err := p.validateAppBindings(apps, vault, volumes); err != nil {
		return "app-bindings", err
	}
	if err := p.validateMoveTargetUploads(volumes, apps); err != nil {
		return "move-uploads", err
	}
	if _, err = p.Storage(after); err != nil {
		return "storage", err
	}
	return "", nil
}
func (p Policy) checkpoint(s state.State, c access.Catalog) (map[string][]byte, state.Code) {
	raw, err := c.Encode()
	if err != nil {
		return nil, state.Invalid
	}
	writes, code := writeCheckpoint(s, CatalogKey, p.Cluster, p.BootstrapKey, c.Revision(), raw)
	if code != state.Applied || !s.Object(ResourcesKey).Present {
		return writes, code
	}
	resources, err := p.Resources(s)
	if err != nil {
		return nil, state.Invalid
	}
	networks, err := resources.Networks.RevokeUnauthorized(c)
	if err != nil {
		return nil, state.Invalid
	}
	if networks.Revision() == resources.Networks.Revision() {
		return writes, code
	}
	resources.Networks = networks
	derived, code := p.resourceCheckpoint(s, resources)
	if code != state.Applied {
		return nil, code
	}
	for key, value := range derived {
		writes[key] = value
	}
	return writes, state.Applied
}

func currentUserKey(c access.Catalog, id string, key [32]byte) bool {
	u, exists := c.User(id)
	if !exists || !u.Enabled {
		return false
	}
	for _, credential := range u.Credentials {
		if credential.Enabled && credential.Method == access.PrivateKey && credential.PublicKey == key {
			return true
		}
	}
	return false
}

// Reduce calls the SAME access functions as the E0 mocks. Bootstrap proof and
// user key admission use the original authenticated Command.Actor, never a
// user/role string copied unchecked from Change.Payload.
func (p Policy) Reduce(s state.State, command state.Command) (map[string][]byte, state.Code) {
	if command.Key == CertificatesKey {
		return p.reduceCertificates(s, command)
	}
	if command.Key == IngressManagementKey {
		return p.reduceIngressManagement(s, command)
	}
	if command.Key == ImageBuildKey {
		return p.reduceImageBuilds(s, command)
	}
	if command.Key == RegistryMaintenanceKey {
		return p.reduceRegistryMaintenance(s, command)
	}
	if command.Key == ImageCacheKey {
		return p.reduceImageCache(s, command)
	}
	if command.Key == NodeShellKey {
		return p.reduceNodeShell(s, command)
	}
	if command.Key == TunnelReconnectKey {
		return p.reduceTunnelReconnect(s, command)
	}
	if command.Key == CompactKey {
		return p.reduceCompactions(s, command)
	}
	if command.Kind == state.ModuleReport && command.Key == CatalogKey {
		return p.reduceTenantRetirementReport(s, command)
	}
	if command.Key == ExternalRegistriesKey {
		return p.reduceExternalRegistries(s, command)
	}
	if (command.Kind == state.Module || command.Kind == state.ModuleReport) && command.Key == RegistriesKey {
		return p.reduceRegistries(s, command)
	}
	if command.Key == LifecycleKey {
		return p.reduceLifecycle(s, command)
	}
	if (command.Kind == state.Module || command.Kind == state.ModuleReport) && command.Key == NodeStorageKey {
		return p.reduceNodeStorage(s, command)
	}
	if command.Kind == state.Module && command.Key == VaultKey {
		if strings.HasPrefix(command.Actor, "node/") {
			return p.reduceVaultApproval(s, command)
		}
		return p.reduceVault(s, command)
	}
	if (command.Kind == state.Module || command.Kind == state.ModuleReport || command.Kind == state.ModuleUpload || command.Kind == state.ModuleAppDown) && command.Key == AppsKey {
		return p.reduceApps(s, command)
	}
	if (command.Kind == state.Module || command.Kind == state.ModuleReport) && command.Key == VolumesKey {
		return p.reduceVolumes(s, command)
	}
	if command.Kind == state.ModuleWindow {
		return p.reduceStorage(s, command)
	}
	if command.Kind == state.Module && command.Key == ResourcesKey {
		return p.reduceResources(s, command)
	}
	if command.Kind == state.Module && command.Key == MembersKey {
		return p.reduceMembers(s, command)
	}
	if command.Kind != state.Module || command.Key != CatalogKey {
		return nil, state.Invalid
	}
	current, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	p = current
	c, err := p.Catalog(s)
	var change Change
	if err != nil {
		return nil, state.Invalid
	}
	if strings.HasPrefix(command.Actor, "user/") {
		op, err := p.Operation(c, command, false)
		if err != nil || p.authorizeChange(s, c, op) != nil {
			return nil, state.Forbidden
		}
		change = op.Change
	} else {
		if c.NodeCLI().DisableNodeCLIOperation {
			return nil, state.Forbidden
		}
		if canonical([]byte(command.Value), &change) != nil || change.Schema != 1 {
			return nil, state.Invalid
		}
		var key [32]byte
		decoded, err := hex.DecodeString(command.Actor)
		if err != nil || len(decoded) != len(key) || hex.EncodeToString(decoded) != command.Actor {
			return nil, state.Forbidden
		}
		copy(key[:], decoded)
		if change.Action != "enroll" && !currentUserKey(c, change.Principal, key) {
			return nil, state.Forbidden
		}
		return p.applyChange(s, c, change, key)
	}
	op, err := p.Operation(c, command, false)
	if err != nil {
		return nil, state.Forbidden
	}
	return p.applyChange(s, c, change, [32]byte{}, &op)
}

func (p Policy) applyChange(s state.State, c access.Catalog, change Change, key [32]byte, origin ...*UserOperation) (map[string][]byte, state.Code) {
	var err error
	var retirementEvidence map[string][]byte
	beforeCatalog := c
	switch change.Action {
	case "set-node-cli-policy":
		var v NodeCLIChange
		if key != ([32]byte{}) || canonical(change.Payload, &v) != nil {
			return nil, state.Forbidden
		}
		c, err = p.nodeKeyContext(s, c)
		if err == nil {
			c, err = c.SetNodeCLI(change.Principal, change.Expected, v.DisableNodeCLIOperation)
		}
	case "enroll":
		var u access.User
		if change.Principal != "" || change.Expected != 0 || canonical(change.Payload, &u) != nil {
			return nil, state.Invalid
		}
		c, err = c.Enroll(key, u)
	case "add-credential":
		var v access.CredentialAddition
		if canonical(change.Payload, &v) != nil {
			return nil, state.Invalid
		}
		c, err = c.AddCredential(change.Principal, p.Cluster, change.Expected, v)
	case "disable-credential":
		var v access.CredentialDisable
		if canonical(change.Payload, &v) != nil {
			return nil, state.Invalid
		}
		c, err = c.DisableCredential(change.Principal, change.Expected, v)
	case "volume-file-grant", "volume-file-revoke":
		var g access.VolumeFileFolderGrant
		if canonical(change.Payload, &g) != nil {
			return nil, state.Invalid
		}
		v, e := p.Volumes(s)
		if e != nil {
			return nil, state.Invalid
		}
		row, ok := v.entries[volumes.Scope{Tenant: g.Tenant, App: g.App, ID: g.Volume}.Key()]
		if !ok || row.State.Deleted() {
			return nil, state.ConditionFailed
		}
		c, err = c.SetVolumeFileGrant(change.Principal, change.Expected, g, change.Action == "volume-file-revoke")
	case "put-user":
		var u access.User
		if canonical(change.Payload, &u) != nil {
			return nil, state.Invalid
		}
		c, err = c.PutUser(change.Principal, change.Expected, u)
	case "set-account-scope":
		var q access.AccountScope
		if canonical(change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		c, err = c.SetAccountScope(change.Principal, change.Expected, q)
	case "issue-initial-credential":
		if key != ([32]byte{}) {
			return nil, state.Forbidden
		}
		c, err = p.installInitialCredential(s, c, change)
	case "create-tenant":
		var v TenantID
		if canonical(change.Payload, &v) != nil {
			return nil, state.Invalid
		}
		c, err = c.CreateTenant(change.Principal, v.ID, change.Expected)
	case "begin-tenant-retirement", "finish-tenant-retirement":
		var selection TenantRetirementSelection
		if canonical(change.Payload, &selection) != nil || selection.Tenant == "" || selection.Operation == "" {
			return nil, state.Invalid
		}
		var targets []access.RetirementTarget
		targets, err = p.tenantInventory(s, selection.Tenant, change.Action == "begin-tenant-retirement")
		if err == nil && change.Action == "begin-tenant-retirement" {
			c, err = c.BeginTenantRetirement(change.Principal, selection.Tenant, selection.Operation, p.Cluster, change.Expected, targets)
			if err == nil {
				tenant, _ := c.Tenant(selection.Tenant)
				r := tenant.Retirement
				raw, marshalErr := json.Marshal(tenantRetirementEvidence{Schema: 1, Tenant: tenant.ID, Operation: r.Operation, StartedRevision: r.StartedRevision, Targets: r.Targets})
				key := tenantRetirementEvidenceKey(tenant.ID, r.Operation)
				if marshalErr != nil || s.Object(key).Revision != 0 {
					return nil, state.Invalid
				}
				var code state.Code
				retirementEvidence, code = writeCheckpoint(s, key, p.Cluster, p.TrustRoot, 1, raw)
				if code != state.Applied {
					return nil, code
				}
			}
		} else if err == nil {
			c, err = c.FinishTenantRetirement(change.Principal, selection.Tenant, selection.Operation, change.Expected, targets)
		}
	case "set-nodes":
		var v NodeAssignment
		if canonical(change.Payload, &v) != nil {
			return nil, state.Invalid
		}

		for _, id := range v.Nodes {
			if _, e := p.nodeOwner(s, id); e != nil {
				return nil, state.Forbidden
			}
		}

		c, err = c.SetNodes(change.Principal, v.Tenant, change.Expected, v.Nodes)
	case "set-membership":
		var v access.Membership
		if canonical(change.Payload, &v) != nil {
			return nil, state.Invalid
		}
		c, err = c.SetMembership(change.Principal, change.Expected, v)
	case "set-trust":
		var v TrustAssignment
		if canonical(change.Payload, &v) != nil {
			return nil, state.Invalid
		}
		c, err = c.SetTrust(change.Principal, v.Tenant, change.Expected, v.Rules)
	case "revoke-session":
		var v SessionRevocation
		if canonical(change.Payload, &v) != nil {
			return nil, state.Invalid
		}
		c, err = c.RevokeSession(change.Principal, v.User, v.Session, change.Expected)
	default:
		return nil, state.Invalid
	}
	if errors.Is(err, access.ErrDenied) {
		return nil, state.Forbidden
	}
	if errors.Is(err, access.ErrConflict) {
		return nil, state.ConditionFailed
	}
	if err != nil {
		return nil, state.Invalid
	}
	if key != ([32]byte{}) && p.nodeShellRawCatalogRevokes(s, beforeCatalog, c) {
		return nil, state.ConditionFailed
	}
	writes, code := p.checkpoint(s, c)
	if code != state.Applied {
		return nil, code
	}
	if len(origin) == 1 && origin[0] != nil {
		closed, closeCode := p.nodeShellCatalogRevocations(s, beforeCatalog, c, *origin[0])
		if closeCode != state.Applied {
			return nil, closeCode
		}
		for key, value := range closed {
			writes[key] = value
		}
	}
	for key, value := range retirementEvidence {
		writes[key] = value
	}
	return writes, code
}
