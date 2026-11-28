// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
)

const maxBuildJobs = 4096
const MaxBuildIntentBytes = 48 << 10

// BuildIntent is immutable accepted metadata, not a container or cache receipt.
// Manifest identifies the exact private CompileBatch; no source/binary bytes
// enter Raft. Job IDs are retained after closure and can never be repurposed.
type BuildIntent struct {
	Schema               uint8
	Cluster              [32]byte
	Tenant, ID, AppUseID string
	AppUse               [32]byte
	Node                 string
	Owner                [32]byte
	Selection            Selection
	Inputs               []BuildInput
	Manifest             [32]byte
	Target               string
	DeadlineUnixMilli    int64
	// Image is the compiler image this job runs: the policy's reference
	// resolved for the parent deploy (repo@sha256:…). Every recipe names it.
	Image string
}

type BuildInput struct{ Content, Recipe [32]byte }

func (b BuildIntent) Clone() BuildIntent {
	b.Selection = b.Selection.Clone()
	b.Inputs = slices.Clone(b.Inputs)
	return b
}
func (b BuildIntent) Digest() [32]byte {
	raw, _ := json.Marshal(b)
	return sha256.Sum256(append([]byte("sfc-checker-build-intent-1\x00"), raw...))
}
func (b BuildIntent) Validate() error {
	if raw, err := json.Marshal(b); err != nil || len(raw) > MaxBuildIntentBytes {
		return ErrContract
	}
	if b.Schema != 1 || b.Cluster == ([32]byte{}) || !name(b.Tenant) || !digest(b.ID) || !name(b.AppUseID) || b.AppUse == ([32]byte{}) || !name(b.Node) || b.Owner == ([32]byte{}) || b.Selection.Validate() != nil || b.Manifest == ([32]byte{}) || b.DeadlineUnixMilli <= 0 || b.Target != "linux/amd64" && b.Target != "linux/arm64" || len(b.Inputs) == 0 || len(b.Inputs) > MaxScripts {
		return ErrContract
	}
	if image, err := access.PinImage(b.Image); err != nil || image.Reference != b.Image {
		return ErrContract
	}
	for i, input := range b.Inputs {
		if input.Content == ([32]byte{}) || input.Recipe == ([32]byte{}) || i > 0 && bytes.Compare(b.Inputs[i-1].Content[:], input.Content[:]) >= 0 {
			return ErrContract
		}
	}
	for _, f := range b.Selection.Sources {
		if f.Cluster != b.Cluster || f.Tenant != b.Tenant {
			return ErrContract
		}
	}
	return nil
}

func (b BuildIntent) ValidateBatch(batch CompileBatch) error {
	if b.Validate() != nil || batch.Validate() != nil || b.ID != batch.Job || b.Tenant != batch.Tenant || b.Target != batch.GOOS+"/"+batch.GOARCH || b.DeadlineUnixMilli != batch.DeadlineUnixMilli || len(b.Inputs) != len(batch.Items) {
		return ErrContract
	}
	raw, _ := json.Marshal(batch)
	if sha256.Sum256(raw) != b.Manifest {
		return ErrContract
	}
	inputs := make([]BuildInput, 0, len(batch.Items))
	for _, item := range batch.Items {
		inputs = append(inputs, BuildInput{item.Source.ContentDigest(), item.Key})
	}
	slices.SortFunc(inputs, func(a, b BuildInput) int { return bytes.Compare(a.Content[:], b.Content[:]) })
	if !slices.Equal(inputs, b.Inputs) {
		return ErrContract
	}
	return nil
}

// ValidateCompilation is consumed before a node stages/starts its original
// manifest. The shared opaque manifest hash alone is not compiler authority.
func (b BuildIntent) ValidateCompilation(policy TenantPolicy, batch CompileBatch) error {
	if b.ValidateBatch(batch) != nil || policy.Validate() != nil || !policy.Enabled || policy.Tenant != b.Tenant || policy.Revision != b.Selection.PolicyRevision || !slices.Contains(policy.Build.Nodes, b.Node) || !slices.Contains(policy.Build.Targets, b.Target) || batch.Toolchain != policy.Build.Toolchain || batch.WorkspaceBytes > policy.Build.WorkspaceBytes || batch.ArtifactBytes > policy.Build.ArtifactBytes || batch.OutputBytes > min(policy.CompiledCacheBytes, policy.Build.WorkspaceBytes) {
		return ErrReference
	}
	if !policy.Build.AllowsCompiler(b.Image) {
		return ErrReference
	}
	for _, item := range batch.Items {
		if item.Recipe.Image != b.Image || !policy.AllowsDescriptor(item.Source) {
			return ErrReference
		}
	}
	return nil
}

// PlanBuild freezes the exact local batch before its member report is signed.
// It does not reserve a slot, issue authority or start a compiler.
func (c Catalog) PlanBuild(parent Use, node string, owner [32]byte, selection Selection, batch CompileBatch) (BuildIntent, error) {
	raw, err := json.Marshal(batch)
	if err != nil || batch.Validate() != nil || parent.Kind != "app-binding" || parent.Tenant != batch.Tenant {
		return BuildIntent{}, ErrContract
	}
	b := BuildIntent{Schema: 1, Cluster: c.Cluster(), Tenant: batch.Tenant, ID: batch.Job, AppUseID: parent.ID, AppUse: parent.Digest(), Node: node, Owner: owner, Selection: selection.Clone(), Manifest: sha256.Sum256(raw), Target: batch.GOOS + "/" + batch.GOARCH, DeadlineUnixMilli: batch.DeadlineUnixMilli}
	if len(batch.Items) > 0 {
		b.Image = batch.Items[0].Recipe.Image
	}
	for _, item := range batch.Items {
		b.Inputs = append(b.Inputs, BuildInput{item.Source.ContentDigest(), item.Key})
	}
	slices.SortFunc(b.Inputs, func(a, b BuildInput) int { return bytes.Compare(a.Content[:], b.Content[:]) })
	if b.ValidateBatch(batch) != nil {
		return BuildIntent{}, ErrContract
	}
	if _, err := c.checkBuildParent(b); err != nil {
		return BuildIntent{}, err
	}
	policy, ok := c.AdmissionPolicy(b.Tenant, b.Selection.PolicyRevision)
	if !ok || b.ValidateCompilation(policy, batch) != nil {
		return BuildIntent{}, ErrReference
	}
	return b, nil
}

// BuildClosure is issued only by the original native owner after its durable
// journal proves no late Create/Start and all owned children/workspace closed.
// Missing observation/EOF/timeout is never such a witness. A removed compiler
// has an exact native ID; not-created requires positive native resolution.
type BuildClosure struct {
	Schema                               uint8
	Cluster, Job, Owner, Journal, Output [32]byte
	Disposition, Native                  string
	Signature                            []byte
	Artifacts                            []BuildArtifact `json:",omitempty"`
}
type BuildArtifact struct {
	Key, Digest [32]byte
	Length      uint64
}

func validateBuildArtifacts(b BuildIntent, artifacts []BuildArtifact) error {
	if len(artifacts) > MaxScripts {
		return ErrContract
	}
	for i, artifact := range artifacts {
		if artifact.Key == ([32]byte{}) || artifact.Digest == ([32]byte{}) || artifact.Length == 0 || artifact.Length > MaxCompiledArtifactBytes || i > 0 && bytes.Compare(artifacts[i-1].Key[:], artifact.Key[:]) >= 0 {
			return ErrContract
		}
		if !slices.ContainsFunc(b.Inputs, func(input BuildInput) bool { return input.Recipe == artifact.Key }) {
			return ErrContract
		}
	}
	return nil
}

func BuildClosureBytes(c BuildClosure) []byte {
	c.Signature = nil
	raw, _ := json.Marshal(c)
	return append([]byte("sfc-checker-build-closure-1\x00"), raw...)
}
func (c BuildClosure) Digest() [32]byte { raw, _ := json.Marshal(c); return sha256.Sum256(raw) }
func (c BuildClosure) Verify(b BuildIntent, phase string) error {
	if c.Schema != 1 || c.Cluster != b.Cluster || c.Job != b.Digest() || c.Owner != b.Owner || c.Journal == ([32]byte{}) || !ed25519.Verify(c.Owner[:], BuildClosureBytes(c), c.Signature) {
		return ErrContract
	}
	if validateBuildArtifacts(b, c.Artifacts) != nil || len(c.Artifacts) > 0 && (c.Disposition != "removed" || c.Output == ([32]byte{})) {
		return ErrContract
	}
	switch c.Disposition {
	case "never-dispatched":
		if phase != "reserved" || c.Native != "" || c.Output != ([32]byte{}) {
			return ErrContract
		}
	case "not-created":
		if phase != "dispatched" || c.Native != "" || c.Output != ([32]byte{}) {
			return ErrContract
		}
	case "removed":
		if phase != "dispatched" || !digest(c.Native) {
			return ErrContract
		}
	default:
		return ErrContract
	}
	return nil
}

type BuildJob struct {
	Intent   BuildIntent
	Revision uint64
	Phase    string
	Closure  *BuildClosure `json:",omitempty"`
}

func (j BuildJob) Clone() BuildJob {
	j.Intent = j.Intent.Clone()
	if j.Closure != nil {
		c := *j.Closure
		c.Signature = slices.Clone(c.Signature)
		c.Artifacts = slices.Clone(c.Artifacts)
		j.Closure = &c
	}
	return j
}

func buildUse(parent Use, b BuildIntent) Use {
	selection := b.Selection.Clone()
	return Use{Tenant: b.Tenant, ID: b.ID, Kind: "build-job", Principal: parent.Principal,
		Node: b.Node, Owner: b.Owner, Parent: b.Digest(), PolicyRevision: selection.PolicyRevision,
		Scripts: selection.Scripts, Sources: selection.Sources}
}

func (c Catalog) BuildJob(tenant, id string) (BuildJob, bool) {
	j, ok := c.d.Builds[catalogKey(tenant, id)]
	return j.Clone(), ok
}

// CompiledOrigin checks historical immutable provenance, not current authority
// or availability. Old builder keys cannot authorize different bytes after the
// original job has closed. The current consumer/provider grant is separate.
func (c Catalog) CompiledOrigin(build CompiledBuild) error {
	if build.Verify() != nil || build.Cluster != c.Cluster() {
		return ErrReference
	}
	j, ok := c.BuildJob(build.Recipe.Tenant, build.ID)
	if !ok || j.Phase != "closed" || j.Closure == nil || j.Intent.Digest() != build.Job || j.Intent.Owner != build.Builder || j.Closure.Verify(j.Intent, "dispatched") != nil || j.Closure.Disposition != "removed" {
		return ErrReference
	}
	policy, ok := c.Policy(j.Intent.Tenant, j.Intent.Selection.PolicyRevision)
	if !ok || !policy.Build.AllowsCompiler(j.Intent.Image) || build.Recipe.Image != j.Intent.Image || build.Recipe.Toolchain != policy.Build.Toolchain || build.Recipe.GOOS+"/"+build.Recipe.GOARCH != j.Intent.Target {
		return ErrReference
	}
	key := build.Recipe.Key()
	if !slices.Contains(j.Intent.Inputs, BuildInput{Content: build.Recipe.Source, Recipe: key}) || !slices.Contains(j.Closure.Artifacts, BuildArtifact{Key: key, Digest: build.Digest, Length: build.Length}) {
		return ErrReference
	}
	return nil
}
func (c Catalog) BuildJobs() []BuildJob {
	keys := make([]string, 0, len(c.d.Builds))
	for key := range c.d.Builds {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out := make([]BuildJob, 0, len(keys))
	for _, key := range keys {
		out = append(out, c.d.Builds[key].Clone())
	}
	return out
}

// selectionContents resolves historical exact versions, without inventing
// current Active state. New acceptance separately goes through Reserve.
func (c Catalog) selectionContents(tenant string, s Selection) ([][32]byte, error) {
	set := map[[32]byte]bool{}
	for _, f := range s.Sources {
		if f.Cluster != c.Cluster() || f.Tenant != tenant {
			return nil, ErrReference
		}
		set[f.ContentDigest()] = true
	}
	for _, ref := range s.Scripts {
		v, ok := c.version(tenant, ref)
		if !ok || v.Deleted {
			return nil, ErrReference
		}
		set[v.Source.ContentDigest()] = true
	}
	out := make([][32]byte, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	return out, nil
}

func (c Catalog) checkBuildParent(b BuildIntent) (Use, error) {
	parent, ok := c.Use(b.Tenant, b.AppUseID)
	if !ok || parent.Kind != "app-binding" || parent.Digest() != b.AppUse || parent.PolicyRevision != b.Selection.PolicyRevision {
		return Use{}, ErrReference
	}
	for _, ref := range b.Selection.Scripts {
		if !slices.Contains(parent.Scripts, ref) {
			return Use{}, ErrReference
		}
	}
	for _, fact := range b.Selection.Sources {
		found := false
		for _, f := range parent.Sources {
			if sameSourceFact(f, fact) {
				found = true
				break
			}
		}
		if !found {
			return Use{}, ErrReference
		}
	}
	contents, err := c.selectionContents(b.Tenant, b.Selection)
	if err != nil || len(contents) != len(b.Inputs) {
		return Use{}, ErrReference
	}
	for i, id := range contents {
		if id != b.Inputs[i].Content {
			return Use{}, ErrReference
		}
	}
	return parent, nil
}

// ReserveBuild is one deterministic FSM candidate: parent join, capacity,
// source/policy pin and immutable job are committed together. No OS effects.
func (c Catalog) ReserveBuild(b BuildIntent) (Catalog, error) {
	if b.Validate() != nil || b.Cluster != c.Cluster() {
		return c, ErrContract
	}
	if old, ok := c.BuildJob(b.Tenant, b.ID); ok {
		if old.Intent.Digest() != b.Digest() {
			return c, ErrPending
		}
		return c, nil // original phase/closure survive duplicate acceptance
	}
	parent, err := c.checkBuildParent(b)
	if err != nil || len(c.d.Builds) >= maxBuildJobs {
		return c, ErrReference
	}
	policy, ok := c.AdmissionPolicy(b.Tenant, b.Selection.PolicyRevision)
	if !ok || !slices.Contains(policy.Build.Targets, b.Target) {
		return c, ErrReference
	}
	live := 0
	for _, j := range c.d.Builds {
		if j.Intent.Tenant == b.Tenant && j.Phase != "closed" {
			live++
		}
	}
	if live >= policy.Build.MaxJobs {
		return c, ErrPending
	}
	n, err := c.reserve(buildUse(parent, b))
	if err != nil {
		return c, err
	}
	if n.d.Builds == nil {
		n.d.Builds = map[string]BuildJob{}
	}
	n.d.Builds[catalogKey(b.Tenant, b.ID)] = BuildJob{Intent: b.Clone(), Revision: 1, Phase: "reserved"}
	if n.Validate() != nil {
		return c, ErrContract
	}
	return n, nil
}

func (c Catalog) DispatchBuild(tenant, id string, expected uint64, owner [32]byte) (Catalog, error) {
	j, ok := c.BuildJob(tenant, id)
	if !ok || j.Intent.Owner != owner || j.Revision != expected || j.Phase != "reserved" {
		return c, ErrPending
	}
	// Current membership/Task/image grant/deadline is checked by the control
	// adapter; this core checks current policy and original source pin too.
	u, ok := c.Use(tenant, id)
	if !ok {
		return c, ErrReference
	}
	for _, input := range j.Intent.Inputs {
		_, p, err := c.SourceForUse(u, input.Content)
		_, admitted := c.AdmissionPolicy(tenant, j.Intent.Selection.PolicyRevision)
		if err != nil || !admitted || !slices.Contains(p.Build.Nodes, j.Intent.Node) || !slices.Contains(p.Build.Targets, j.Intent.Target) {
			return c, ErrReference
		}
	}
	n, err := c.advance()
	if err != nil {
		return c, err
	}
	j.Phase, j.Revision = "dispatched", j.Revision+1
	n.d.Builds[catalogKey(tenant, id)] = j
	return n, nil
}

func (c Catalog) CloseBuild(tenant, id string, expected uint64, closure BuildClosure) (Catalog, error) {
	j, ok := c.BuildJob(tenant, id)
	if !ok {
		return c, ErrReference
	}
	if j.Phase == "closed" {
		a, _ := json.Marshal(j.Closure)
		b, _ := json.Marshal(closure)
		if !bytes.Equal(a, b) {
			return c, ErrPending
		}
		return c, nil
	}
	if j.Revision != expected || closure.Verify(j.Intent, j.Phase) != nil {
		return c, ErrPending
	}
	u, ok := c.Use(tenant, id)
	if !ok {
		return c, ErrReference
	}
	n, err := c.release(u)
	if err != nil {
		return c, err
	}
	j.Revision++
	j.Phase = "closed"
	j.Closure = &closure
	n.d.Builds[catalogKey(tenant, id)] = j.Clone()
	if n.Validate() != nil {
		return c, ErrContract
	}
	return n, nil
}

func (c Catalog) validateBuildJobs() error {
	if len(c.d.Builds) > maxBuildJobs {
		return ErrContract
	}
	for key, j := range c.d.Builds {
		b := j.Intent
		if b.Validate() != nil || b.Cluster != c.Cluster() || key != catalogKey(b.Tenant, b.ID) {
			return ErrContract
		}
		if _, ok := c.Policy(b.Tenant, b.Selection.PolicyRevision); !ok {
			return ErrContract
		}
		switch j.Phase {
		case "reserved", "dispatched":
			if j.Closure != nil || j.Phase == "reserved" && j.Revision != 1 || j.Phase == "dispatched" && j.Revision != 2 {
				return ErrContract
			}
			parent, err := c.checkBuildParent(b)
			u, ok := c.Use(b.Tenant, b.ID)
			if err != nil || !ok || !sameUse(u, buildUse(parent, b)) {
				return ErrContract
			}
		case "closed":
			if j.Closure == nil || j.Revision != 2 && j.Revision != 3 {
				return ErrContract
			}
			prior := "reserved"
			if j.Revision == 3 {
				prior = "dispatched"
			}
			if j.Closure.Verify(b, prior) != nil {
				return ErrContract
			}
			if _, ok := c.Use(b.Tenant, b.ID); ok {
				return ErrContract
			}
		default:
			return ErrContract
		}
	}
	for _, u := range c.d.Uses {
		if u.Kind == "build-job" {
			j, ok := c.BuildJob(u.Tenant, u.ID)
			if !ok || j.Phase == "closed" || u.Parent != j.Intent.Digest() {
				return ErrContract
			}
		}
	}
	return nil
}
