// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/secrets"
)

// These are approval/usage namespaces, never app/Task resources. Purpose and
// the accepted job identity separate build mounts from app/source consumers.
func ImageBuildSecretConsumer(spec imagebuild.JobSpec) string {
	h := sha256.Sum256([]byte("sfc-imagebuild-secret-consumer-1\x00" + spec.Tenant + "\x00" + spec.ID))
	return "build-" + hex.EncodeToString(h[:24])
}
func ImageBuildSecretUses(spec imagebuild.JobSpec, session access.Session) map[string][]secrets.Use {
	return imageBuildSecretUsesFor(spec.Tenant, spec.Context.ID, spec.ID, spec.Scope.Root.Node, spec.Scope.Root.Key, spec.Context.Secrets, session)
}

// ImageBuildSecretScope is the stable approval namespace shared by the build
// plan and its CLI journal. It does not change with a context revision or job.
func ImageBuildSecretScope(tenant, contextID string) string {
	h := sha256.Sum256([]byte("sfc-imagebuild-secret-context-1\x00" + tenant + "\x00" + contextID))
	return "build-" + hex.EncodeToString(h[:24])
}

func imageBuildSecretUsesFor(tenant, contextID, jobID, node string, nodeKey [32]byte, refs []imagebuild.SecretMount, session access.Session) map[string][]secrets.Use {
	app := ImageBuildSecretScope(tenant, contextID)
	uses := map[string][]secrets.Use{}
	for _, ref := range refs {
		rows := uses[ref.Realm]
		if len(rows) == 0 {
			rows = []secrets.Use{{Purpose: secrets.PurposeImageBuild, Tenant: tenant, User: session.User, App: app, Deployment: jobID, Service: "builder", Node: node, NodeKey: nodeKey, RequesterKey: session.Key}}
		}
		if !slices.Contains(rows[0].Sources, ref.Secret) {
			rows[0].Sources = append(rows[0].Sources, ref.Secret)
		}
		uses[ref.Realm] = rows
	}
	return uses
}
func ValidImageBuildSecretUses(plan ImageBuildJobPlan, session access.Session) bool {
	want := ImageBuildSecretUses(plan.Spec, session)
	return plan.Spec.Cluster == session.Cluster && len(want) == len(plan.Uses) && (len(want) == 0 || buildJSONEqual(want, plan.Uses))
}

func (p Policy) acquireImageBuildSecrets(s state.State, row *ImageBuildJobRecord, writes map[string][]byte) error {
	if len(row.Run.Spec.Context.Secrets) == 0 {
		return nil
	}
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	spec := row.Run.Spec
	if c.AuthorizeAccepted(row.Origin.Session, p.Cluster, row.Origin.At, spec.Tenant, access.Deploy, spec.Scope.Root.Node) != nil {
		return access.ErrDenied
	}
	v, err := p.Vault(s)
	if err != nil {
		return err
	}
	uses := ImageBuildSecretUses(spec, row.Origin.Session)
	acquiredAt, err := v.Approvals.CommittedUseTime(c, v.Trees, uses, row.acquisitionAt())
	if err != nil {
		return err
	}
	var realms []string
	for realm := range uses {
		realms = append(realms, realm)
	}
	slices.Sort(realms)
	for _, realm := range realms {
		tree, ok := v.Trees[realm]
		if !ok {
			return access.ErrDenied
		}
		var grant secrets.Grant
		v.Approvals, grant, err = v.Approvals.Acquire(c, tree, uses[realm][0], ImageBuildSecretConsumer(spec), 1, v.Approvals.Revision(), acquiredAt)
		if err != nil {
			return err
		}
		row.Grants = append(row.Grants, grant)
	}
	// Reject missing declared keys/providers before publishing any reservation.
	reads, err := p.bindingGrantReads(s, v, c, row.Grants, acquiredAt)
	if err != nil {
		return err
	}
	if _, err := imageBuildSecretReadInputs(spec, reads); err != nil {
		return err
	}
	extra, code := p.vaultCheckpoint(s, v)
	if code != state.Applied {
		return ErrCatalog
	}
	for key, value := range extra {
		writes[key] = value
	}
	return nil
}

func validImageBuildSecretProof(spec imagebuild.JobSpec, grant secrets.Grant, proof secrets.UseGone) bool {
	u := grant.Use
	return proof.Purpose == secrets.PurposeImageBuild && proof.Cluster == spec.Cluster && proof.Realm == grant.Realm && proof.Tenant == spec.Tenant && proof.App == u.App && proof.Deployment == u.Deployment && proof.Consumer == grant.Consumer && proof.Generation == grant.Generation && proof.NodeKey == spec.Scope.Root.Key && proof.Selection == grant.Selection && proof.Lifetime == grant.Lifetime && proof.Stopped && proof.MountsGone && ed25519.Verify(proof.NodeKey[:], secrets.UseGoneBytes(proof), proof.Signature)
}
func validImageBuildSecretGrants(row ImageBuildJobRecord) bool {
	spec := row.Run.Spec
	uses := ImageBuildSecretUses(spec, row.Origin.Session)
	if len(uses) != len(row.Grants) {
		return false
	}
	last := ""
	for i, grant := range row.Grants {
		rows, ok := uses[grant.Realm]
		if !ok || len(rows) != 1 || i > 0 && grant.Realm <= last || !buildJSONEqual(grant.Use, rows[0]) || grant.Consumer != ImageBuildSecretConsumer(spec) || grant.Generation != 1 || grant.Selection == ([32]byte{}) || grant.Lifetime.Token == 0 {
			return false
		}
		last = grant.Realm
	}
	if row.Run.Terminal() {
		if row.Progress == nil || len(row.Progress.Secrets) != len(row.Grants) {
			return false
		}
		for i, grant := range row.Grants {
			if !validImageBuildSecretProof(spec, grant, row.Progress.Secrets[i]) {
				return false
			}
		}
	}
	return true
}
func (p Policy) validateImageBuildSecretRefs(s state.State, b ImageBuildCatalog) error {
	v, err := p.Vault(s)
	if err != nil {
		return err
	}
	for _, row := range b.Jobs {
		if !validImageBuildSecretGrants(row) {
			return ErrCatalog
		}
		for _, grant := range row.Grants {
			_, exists := v.Approvals.Usage(grant)
			if exists == row.Run.Terminal() {
				return ErrCatalog
			}
		}
	}
	return nil
}

func imageBuildSecretReadInputs(spec imagebuild.JobSpec, reads []AppInputRead) ([]RegistryImageInput, error) {
	var out []RegistryImageInput
	for _, ref := range spec.Context.Secrets {
		found := false
		for _, read := range reads {
			if read.Realm != ref.Realm {
				continue
			}
			for _, leaf := range read.Plan.Leaves {
				if leaf.Secret != ref.Secret || !slices.Contains(leaf.Reference.Keys, ref.Key) {
					continue
				}
				for _, provider := range read.Profiles {
					if provider.ID != leaf.Reference.Profile || !provider.Enabled || !provider.Values {
						continue
					}
					if !slices.ContainsFunc(out, func(v RegistryImageInput) bool { return v.Realm == ref.Realm && v.Leaf.Secret == ref.Secret }) {
						out = append(out, RegistryImageInput{Realm: ref.Realm, Leaf: leaf, Provider: provider})
					}
					found = true
				}
			}
		}
		if !found {
			return nil, access.ErrDenied
		}
	}
	return out, nil
}

type ImageBuildSecretSelection struct {
	Tenant, Job string
	Snapshot    [32]byte
}
type ImageBuildSecretRequest struct {
	Selection ImageBuildSecretSelection
	At        int64
}
type ImageBuildSecretInputs struct {
	Selection    ImageBuildSecretSelection
	Inputs       RegistryImageInputs
	Index, Epoch uint64
}

func (p Policy) ImageBuildSecretInputs(s state.State, caller [32]byte, q ImageBuildSecretRequest) (ImageBuildSecretInputs, error) {
	work, err := p.ImageBuildJobWork(s, caller, ImageBuildJobWorkQuery{Tenant: q.Selection.Tenant, ID: q.Selection.Job, At: q.At})
	if err != nil || !work.Allowed || work.Run.Phase != "running" || q.Selection.Snapshot != work.Run.Spec.Digest() {
		return ImageBuildSecretInputs{}, access.ErrDenied
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildSecretInputs{}, err
	}
	row, ok := b.Job(q.Selection.Tenant, q.Selection.Job)
	if !ok {
		return ImageBuildSecretInputs{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageBuildSecretInputs{}, err
	}
	v, err := p.Vault(s)
	if err != nil {
		return ImageBuildSecretInputs{}, err
	}
	reads, err := p.bindingGrantReads(s, v, c, row.Grants, q.At)
	if err != nil {
		return ImageBuildSecretInputs{}, err
	}
	entries, err := imageBuildSecretReadInputs(work.Run.Spec, reads)
	if err != nil {
		return ImageBuildSecretInputs{}, err
	}
	raw, err := json.Marshal(struct {
		Selection ImageBuildSecretSelection
		Reads     []AppInputRead
	}{q.Selection, reads})
	if err != nil || len(raw) > 96<<10 {
		return ImageBuildSecretInputs{}, access.ErrInvalid
	}
	return ImageBuildSecretInputs{Selection: q.Selection, Inputs: RegistryImageInputs{ReadSet: sha256.Sum256(append([]byte("sfc-imagebuild-secret-read-1\x00"), raw...)), Entries: entries}, Index: s.Index(), Epoch: s.ModuleEpoch()}, nil
}

func (p Policy) imageBuildApprovalUses(s state.State, session access.Session, at int64, origin *UserOperation, selection *AppApprovalSelection) (map[string][]secrets.Use, error) {
	if origin == nil || selection != nil || origin.VerifyOriginal(p.Cluster) != nil || origin.Session.User != session.User || origin.Change.Principal != session.User || origin.Change.Action != "begin-image-build" || origin.Change.Expected != 0 || at < origin.At {
		return nil, access.ErrDenied
	}
	var q ImageBuildJobStart
	if canonical(origin.Change.Payload, &q) != nil {
		return nil, access.ErrDenied
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return nil, err
	}
	var spec imagebuild.JobSpec
	if row, ok := b.Job(q.Tenant, q.ID); ok {
		if row.Run.Terminal() || row.Run.Cancel || !bytes.Equal(OperationBytes(row.Origin), OperationBytes(*origin)) || !bytes.Equal(row.Origin.Signature, origin.Signature) {
			return nil, access.ErrDenied
		}
		spec = row.Run.Spec
	} else {
		if origin.RootRevision != s.Object(ImageBuildKey).Revision || origin.Epoch != s.ModuleEpoch() {
			return nil, access.ErrConflict
		}
		plan, err := p.ImageBuildJobPlan(s, origin.Session, int64(q.At), q.Tenant, ImageBuildJobQuery{ID: q.ID, Context: q.Context, Version: q.Version})
		if err != nil || plan.Change != q {
			return nil, access.ErrDenied
		}
		spec = plan.Spec
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, err
	}
	for _, action := range []access.Action{access.ManageRegistry, access.Deploy} {
		if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, spec.Tenant, action, spec.Scope.Root.Node) != nil || c.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, spec.Tenant, action, spec.Scope.Root.Node) != nil {
			return nil, access.ErrDenied
		}
	}
	if c.OperationAllowed(session, "begin-image-build") != nil || c.OperationAllowed(origin.Session, "begin-image-build") != nil {
		return nil, access.ErrDenied
	}
	return ImageBuildSecretUses(spec, origin.Session), nil
}

func (p Policy) admitImageBuildVaultPatch(s state.State, cmd state.Command, keys []string) bool {
	writes, code := p.reduceImageBuilds(s, cmd)
	if code != state.Applied {
		return false
	}
	count := 0
	for key := range writes {
		if key == VaultKey || strings.HasPrefix(key, VaultKey+"/") {
			count++
		}
	}
	if len(keys) != count {
		return false
	}
	for _, key := range keys {
		if !checkpointPatchKey(writes, VaultKey, key) {
			return false
		}
	}
	return true
}
