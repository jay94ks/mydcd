// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagesource"
	"github.com/jay94ks/seafield/internal/secrets"
)

// The source reader is a public authorization/usage record, not an app Task,
// process, network login result or independent Vault backend.
type ExternalRegistryReader struct {
	Spec       imagesource.Source
	Node       string
	Owner      [32]byte
	Generation uint64
	Origin     UserOperation
	Grants     []secrets.Grant
	Draining   bool
}
type ExternalRegistryBind struct {
	Tenant, ID, Node string
	Definition       [32]byte
}
type ExternalRegistryBindPlan struct {
	Schema                        uint8
	Cluster                       [32]byte
	Selection                     ExternalRegistryBind
	Spec                          imagesource.Source
	Expected, RootRevision, Epoch uint64
	Uses                          map[string][]secrets.Use
}
type ExternalRegistryBindQuery struct{ ID, Node string }

func (q ExternalRegistryBindQuery) Valid() bool { return validID(q.ID) && validID(q.Node) }

func (plan ExternalRegistryBindPlan) Valid(session access.Session, tenant string, q ExternalRegistryBindQuery) bool {
	if !q.Valid() || plan.Schema != 1 || plan.Cluster != session.Cluster || plan.Selection.Tenant != tenant || plan.Selection.ID != q.ID || plan.Selection.Node != q.Node || plan.Spec.Tenant != tenant || plan.Spec.ID != q.ID || plan.Spec.Validate() != nil || !plan.Spec.Enabled || plan.Selection.Definition != ExternalRegistryDefinition(plan.Spec) || plan.Expected == 0 || plan.RootRevision == 0 || plan.Epoch == 0 {
		return false
	}
	var owner [32]byte
	for _, uses := range plan.Uses {
		if len(uses) != 1 || uses[0].NodeKey == ([32]byte{}) {
			return false
		}
		if owner != ([32]byte{}) && owner != uses[0].NodeKey {
			return false
		}
		owner = uses[0].NodeKey
	}
	expected := externalRegistryUses(plan.Spec, UserOperation{Session: session}, q.Node, owner)
	if len(expected) != len(plan.Uses) {
		return false
	}
	for realm, use := range expected {
		uses := plan.Uses[realm]
		if len(uses) != 1 {
			return false
		}
		a, _ := json.Marshal(use)
		b, _ := json.Marshal(uses[0])
		if string(a) != string(b) {
			return false
		}
	}
	return true
}

func ExternalRegistryDefinition(spec imagesource.Source) [32]byte {
	raw, _ := json.Marshal(spec)
	return sha256.Sum256(append([]byte("sfc-external-registry-definition-1\x00"), raw...))
}

// ExternalRegistryScope is the stable approval namespace; Purpose separates it
// from any app that happens to use the same public name.
func ExternalRegistryScope(tenant, id string) string {
	raw, _ := json.Marshal(RegistrySelection{tenant, id})
	h := sha256.Sum256(append([]byte("sfc-external-registry-namespace-1\x00"), raw...))
	return "registry-" + hex.EncodeToString(h[:24])
}
func externalRegistryUses(spec imagesource.Source, origin UserOperation, node string, owner [32]byte) map[string]secrets.Use {
	scope := ExternalRegistryScope(spec.Tenant, spec.ID)
	uses := map[string]secrets.Use{}
	for _, ref := range spec.References() {
		use, ok := uses[ref.Realm]
		if !ok {
			use = secrets.Use{Purpose: secrets.PurposeRegistrySource, Tenant: spec.Tenant, User: origin.Session.User, App: scope, Deployment: scope, Service: "registry", Node: node, NodeKey: owner, RequesterKey: origin.Session.Key}
		}
		// A cluster source reader reads only to pull images, so a
		// RegistryShared cluster secret may serve it. A workspace source's
		// reader never may, even when it names a cluster secret.
		use.Sources = append(use.Sources, ref.ID)
		if spec.Cluster() {
			use.RegistrySources = append(use.RegistrySources, ref.ID)
		}
		uses[ref.Realm] = use
	}
	return uses
}

func (p Policy) PlanExternalRegistryBind(s state.State, session access.Session, at int64, tenant, id, node string) (ExternalRegistryBindPlan, error) {
	p, err := p.Current(s)
	if err != nil {
		return ExternalRegistryBindPlan{}, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ExternalRegistryBindPlan{}, err
	}
	if !validSourceOwner(tenant) || !validID(id) || !validID(node) || c.OperationAllowed(session, "bind-external-registry") != nil || p.authorizeSourceOwner(c, session, at, tenant, node, false) != nil {
		return ExternalRegistryBindPlan{}, access.ErrDenied
	}
	owner, err := p.workNodeOwner(s, node)
	if err != nil {
		return ExternalRegistryBindPlan{}, err
	}
	entries, err := p.ExternalRegistries(s)
	if err != nil {
		return ExternalRegistryBindPlan{}, err
	}
	for _, entry := range entries {
		if entry.Spec.Tenant != tenant || entry.Spec.ID != id {
			continue
		}
		if entry.Deleted || !entry.Spec.Enabled || entry.Reader != nil {
			return ExternalRegistryBindPlan{}, access.ErrConflict
		}
		uses := map[string][]secrets.Use{}
		for realm, use := range externalRegistryUses(entry.Spec, UserOperation{Session: session}, node, owner) {
			uses[realm] = []secrets.Use{use}
		}
		return ExternalRegistryBindPlan{Schema: 1, Cluster: p.Cluster, Selection: ExternalRegistryBind{tenant, id, node, ExternalRegistryDefinition(entry.Spec)}, Spec: imagesource.Own(entry.Spec), Expected: entry.Revision, RootRevision: s.Object(ExternalRegistriesKey).Revision, Epoch: s.ModuleEpoch(), Uses: uses}, nil
	}
	return ExternalRegistryBindPlan{}, access.ErrDenied
}

func (p Policy) validExternalRegistryReader(s state.State, reader ExternalRegistryReader, selection RegistrySelection) bool {
	if reader.Spec.Validate() != nil || reader.Spec.Tenant != selection.Tenant || reader.Spec.ID != selection.ID || !reader.Spec.Enabled || reader.Generation == 0 || reader.Owner == ([32]byte{}) || !validID(reader.Node) || reader.Origin.VerifyOriginal(p.Cluster) != nil || reader.Origin.Change.Action != "bind-external-registry" || reader.Origin.Change.Expected != reader.Generation-1 {
		return false
	}
	var bind ExternalRegistryBind
	if canonical(reader.Origin.Change.Payload, &bind) != nil || bind.Tenant != selection.Tenant || bind.ID != selection.ID || bind.Node != reader.Node || bind.Definition != ExternalRegistryDefinition(reader.Spec) {
		return false
	}
	members, err := p.Members(s)
	if err != nil {
		return false
	}
	entry, ok := members.Entry(reader.Node)
	if !ok || entry.Peer.Key != hex.EncodeToString(reader.Owner[:]) {
		return false
	}
	uses := externalRegistryUses(reader.Spec, reader.Origin, reader.Node, reader.Owner)
	if len(reader.Grants) != len(uses) {
		return false
	}
	last := ""
	for i, grant := range reader.Grants {
		use, ok := uses[grant.Realm]
		a, _ := json.Marshal(use)
		b, _ := json.Marshal(grant.Use)
		if !ok || string(a) != string(b) || i > 0 && grant.Realm <= last || grant.Consumer != ExternalRegistryScope(selection.Tenant, selection.ID) || grant.Generation != reader.Generation || grant.Selection == ([32]byte{}) || grant.Lifetime.Token == 0 {
			return false
		}
		last = grant.Realm
	}
	return true
}

func (p Policy) bindExternalRegistry(s state.State, entry ExternalRegistryEntry, op UserOperation, q ExternalRegistryBind) (ExternalRegistryReader, Vault, error) {
	owner, err := p.workNodeOwner(s, q.Node)
	if err != nil {
		return ExternalRegistryReader{}, Vault{}, err
	}
	if entry.Deleted || !entry.Spec.Enabled || entry.Reader != nil || q.Definition != ExternalRegistryDefinition(entry.Spec) {
		return ExternalRegistryReader{}, Vault{}, access.ErrConflict
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ExternalRegistryReader{}, Vault{}, err
	}
	vault, err := p.Vault(s)
	if err != nil {
		return ExternalRegistryReader{}, Vault{}, err
	}
	reader := ExternalRegistryReader{Spec: imagesource.Own(entry.Spec), Node: q.Node, Owner: owner, Generation: entry.Revision + 1, Origin: op}
	uses := externalRegistryUses(entry.Spec, op, q.Node, owner)
	approvalUses := make(map[string][]secrets.Use, len(uses))
	for realm, use := range uses {
		approvalUses[realm] = []secrets.Use{use}
	}
	acquiredAt, err := vault.Approvals.CommittedUseTime(c, vault.Trees, approvalUses, op.At)
	if err != nil {
		return ExternalRegistryReader{}, Vault{}, err
	}
	realms := make([]string, 0, len(uses))
	for realm := range uses {
		realms = append(realms, realm)
	}
	slices.Sort(realms)
	for _, realm := range realms {
		tree, ok := vault.Trees[realm]
		if !ok {
			return ExternalRegistryReader{}, Vault{}, access.ErrDenied
		}
		var grant secrets.Grant
		vault.Approvals, grant, err = vault.Approvals.Acquire(c, tree, uses[realm], ExternalRegistryScope(entry.Spec.Tenant, entry.Spec.ID), reader.Generation, vault.Approvals.Revision(), acquiredAt)
		if err != nil {
			return ExternalRegistryReader{}, Vault{}, err
		}
		reader.Grants = append(reader.Grants, grant)
	}
	return reader, vault, nil
}

// Owner closure is accepted only after shared Drain and the owner's actual
// original query/Secret/HTTP I/O join. No metadata-only count grants closure.
type ExternalRegistryReaderClosed struct {
	Schema                                 uint8
	Cluster, Owner                         [32]byte
	Tenant, ID                             string
	Generation, Index, Epoch, RootRevision uint64
	At                                     int64
	Closed                                 bool
	Pending                                uint64
	Secrets                                []secrets.UseGone
	Signature                              []byte
}

func ExternalRegistryReaderClosedBytes(q ExternalRegistryReaderClosed) []byte {
	q.Signature = nil
	raw, _ := json.Marshal(q)
	return append([]byte("sfc-external-registry-reader-closed-1\x00"), raw...)
}
func (q ExternalRegistryReaderClosed) Command() (state.Command, error) {
	raw, err := json.Marshal(q)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(q.Owner[:]), Epoch: q.Epoch, Key: ExternalRegistriesKey, Expected: q.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func (p Policy) validExternalRegistryClosure(reader ExternalRegistryReader, q ExternalRegistryReaderClosed) bool {
	if q.Schema != 1 || q.Cluster != p.Cluster || q.Owner != reader.Owner || q.Tenant != reader.Spec.Tenant || q.ID != reader.Spec.ID || q.Generation != reader.Generation || !q.Closed || q.Pending != 0 || q.At <= 0 || q.Index == 0 || q.Epoch == 0 || !ed25519.Verify(q.Owner[:], ExternalRegistryReaderClosedBytes(q), q.Signature) || len(q.Secrets) != len(reader.Grants) {
		return false
	}
	for i, grant := range reader.Grants {
		proof := q.Secrets[i]
		if proof.Purpose != grant.Use.Purpose || proof.Cluster != p.Cluster || proof.Realm != grant.Realm || proof.Tenant != grant.Use.Tenant || proof.App != grant.Use.App || proof.Deployment != grant.Use.Deployment || proof.Consumer != grant.Consumer || proof.Generation != grant.Generation || proof.NodeKey != reader.Owner || proof.Selection != grant.Selection || proof.Lifetime != grant.Lifetime || !proof.Stopped || !proof.MountsGone || !ed25519.Verify(reader.Owner[:], secrets.UseGoneBytes(proof), proof.Signature) {
			return false
		}
	}
	return true
}

type ExternalRegistryReaderClosure struct {
	Reader ExternalRegistryReader
	Proof  ExternalRegistryReaderClosed
}

type ExternalRegistryReadSelection struct {
	Tenant, ID string
	Generation uint64
}
type ExternalRegistryWorkRequest struct {
	Selection ExternalRegistryReadSelection
	At        int64
}
type ExternalRegistryWork struct {
	Reader       ExternalRegistryReader
	Inputs       RegistryImageInputs
	Index, Epoch uint64
}

// Work authorizes transient credential I/O only for the original installed
// source reader. It grants no public query or remote mutation: read services
// and signed maintenance jobs separately check user/action/repository scope.
func (p Policy) ExternalRegistryWork(s state.State, caller [32]byte, q ExternalRegistryWorkRequest) (ExternalRegistryWork, error) {
	if q.At <= 0 || q.Selection.Generation == 0 {
		return ExternalRegistryWork{}, access.ErrDenied
	}
	p, err := p.Current(s)
	if err != nil {
		return ExternalRegistryWork{}, err
	}
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(caller) {
		return ExternalRegistryWork{}, access.ErrDenied
	}
	entries, err := p.ExternalRegistries(s)
	if err != nil {
		return ExternalRegistryWork{}, err
	}
	for _, entry := range entries {
		if entry.Spec.Tenant != q.Selection.Tenant || entry.Spec.ID != q.Selection.ID {
			continue
		}
		reader := entry.Reader
		if entry.Deleted || !entry.Spec.Enabled || reader == nil || reader.Draining || reader.Owner != caller || reader.Generation != q.Selection.Generation || !imagesource.Equal(reader.Spec, entry.Spec) {
			return ExternalRegistryWork{}, access.ErrDenied
		}
		owner, err := p.workNodeOwner(s, reader.Node)
		if err != nil || owner != caller {
			return ExternalRegistryWork{}, access.ErrDenied
		}
		c, err := p.Catalog(s)
		if err != nil {
			return ExternalRegistryWork{}, err
		}
		if c.OperationAllowed(reader.Origin.Session, "bind-external-registry") != nil || p.authorizeAcceptedSourceOwner(c, reader.Origin, entry.Spec.Tenant, reader.Node) != nil {
			return ExternalRegistryWork{}, access.ErrDenied
		}
		vault, err := p.Vault(s)
		if err != nil {
			return ExternalRegistryWork{}, err
		}
		reads, err := p.bindingGrantReads(s, vault, c, reader.Grants, q.At)
		if err != nil {
			return ExternalRegistryWork{}, err
		}
		inputs, err := registrySourceReadInputs(entry.Spec, reads)
		if err != nil {
			return ExternalRegistryWork{}, err
		}
		encoded, err := json.Marshal(struct {
			Selection ExternalRegistryReadSelection
			Spec      imagesource.Source
			Owner     [32]byte
			Reads     []AppInputRead
		}{q.Selection, entry.Spec, reader.Owner, reads})
		if err != nil {
			return ExternalRegistryWork{}, err
		}
		return ExternalRegistryWork{Reader: *reader, Inputs: RegistryImageInputs{ReadSet: sha256.Sum256(encoded), Entries: inputs}, Index: s.Index(), Epoch: s.ModuleEpoch()}, nil
	}
	return ExternalRegistryWork{}, access.ErrDenied
}

func (p Policy) externalRegistryCloseReport(s state.State, cmd state.Command) (ExternalRegistryReaderClosed, error) {
	var q ExternalRegistryReaderClosed
	if cmd.Kind != state.ModuleReport || cmd.Key != ExternalRegistriesKey || canonical([]byte(cmd.Value), &q) != nil {
		return q, access.ErrDenied
	}
	want, err := q.Command()
	if err != nil || want != cmd || q.Epoch != s.ModuleEpoch() || q.Index > s.Index() {
		return q, access.ErrDenied
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(q.Owner) {
		return q, access.ErrDenied
	}
	entries, err := p.ExternalRegistries(s)
	if err != nil {
		return q, err
	}
	for _, entry := range entries {
		if entry.Spec.Tenant == q.Tenant && entry.Spec.ID == q.ID && entry.Reader != nil && entry.Reader.Draining && p.validExternalRegistryClosure(*entry.Reader, q) {
			selection := ExternalRegistryReadSelection{Tenant: q.Tenant, ID: q.ID, Generation: q.Generation}
			if held, err := p.ExternalRegistryImageBuildsPending(s, selection); err != nil || held {
				return q, access.ErrDenied
			}
			return q, nil
		}
	}
	return q, access.ErrDenied
}

func (p Policy) ResolveExternalRegistryClose(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var report ExternalRegistryReaderClosed
	if canonical(raw, &report) != nil || report.Owner != caller || !ed25519.Verify(caller[:], ExternalRegistryReaderClosedBytes(report), report.Signature) {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := report.Command()
	if err != nil {
		return state.Command{}, err
	}
	if _, found := s.LookupResult(cmd); found {
		return cmd, nil
	}
	if _, err = p.externalRegistryCloseReport(s, cmd); err != nil {
		return state.Command{}, err
	}
	return cmd, nil
}
func (p Policy) reduceExternalRegistryClose(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	q, err := p.externalRegistryCloseReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	entries, err := p.ExternalRegistries(s)
	if err != nil {
		return nil, state.Invalid
	}
	vault, err := p.Vault(s)
	if err != nil {
		return nil, state.Invalid
	}
	for i, entry := range entries {
		if entry.Spec.Tenant != q.Tenant || entry.Spec.ID != q.ID {
			continue
		}
		for _, proof := range q.Secrets {
			vault.Approvals, err = vault.Approvals.ReleaseUse(proof)
			if err != nil {
				return nil, state.ConditionFailed
			}
		}
		entry.Closed = &ExternalRegistryReaderClosure{Reader: *entry.Reader, Proof: q}
		entry.Reader = nil
		entries[i] = entry
		writes, code := p.externalRegistryCheckpoint(s, entries)
		if code != state.Applied {
			return nil, code
		}
		if len(q.Secrets) > 0 {
			extra, code := p.vaultCheckpoint(s, vault)
			if code != state.Applied {
				return nil, code
			}
			for k, v := range extra {
				writes[k] = v
			}
		}
		return writes, state.Applied
	}
	return nil, state.ConditionFailed
}

func (p Policy) admitExternalRegistryVaultPatch(s state.State, cmd state.Command, keys []string) bool {
	if cmd.Key != ExternalRegistriesKey {
		return false
	}
	current, err := p.Current(s)
	if err != nil {
		return false
	}
	p = current
	if strings.HasPrefix(cmd.Actor, "node/") {
		if _, err := p.externalRegistryCloseReport(s, cmd); err != nil {
			return false
		}
	} else {
		c, err := p.Catalog(s)
		if err != nil {
			return false
		}
		op, err := p.Operation(c, cmd, false)
		if err != nil || op.Change.Action != "bind-external-registry" || p.authorizeExternalRegistry(c, op) != nil {
			return false
		}
	}
	for _, key := range keys {
		if key != VaultKey && !strings.HasPrefix(key, VaultKey+"/") {
			return false
		}
	}
	return true
}
