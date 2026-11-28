// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/distribution/reference"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
)

// JobSpec fixes the accepted inputs. Public ARGs and Secret references remain
// distinct; no Vault values, Docker credentials or mutable source paths occur.
type JobSpec struct {
	Schema                          uint8
	Cluster                         [32]byte
	Tenant, ID                      string
	Version                         [32]byte
	Number                          uint64
	Scope                           UploadScope
	Seal                            SealReceipt
	Context                         ContextSpec
	Policy                          Policy
	ContextRevision, PolicyRevision uint64
	RegistryAuthority               string
	RegistryGeneration              uint64
	RegistrySpec                    [32]byte
	Commit                          string `json:",omitempty"`
	CreatedAt                       uint64
}

func (s JobSpec) Digest() [32]byte { return digestJSON("sfc-imagebuild-job-1", s) }
func (s JobSpec) Shape() error {
	if s.Schema != 1 || !lifecycle.ValidID(s.ID) || s.Cluster == ([32]byte{}) || s.Policy.Validate(s.Cluster) != nil || s.Context.Validate() != nil || !s.Context.Under(s.Policy) || s.Context.Tenant != s.Tenant || s.Scope.Validate() != nil || s.Scope.Cluster != s.Cluster || s.Scope.Tenant != s.Tenant || s.Scope.Context != s.Context.ID || s.Scope.Root != s.Context.Root || s.Scope.Dockerfile != s.Context.Dockerfile || s.Seal.Schema != 1 || s.Seal.Scope != s.Scope.Hash() || s.Seal.ZIP != s.Scope.Digest || s.Seal.Tree == ([32]byte{}) || s.Seal.Entries == 0 || s.Seal.Entries > MaxTreeEntries || s.Seal.ExpandedBytes < 0 || s.Seal.ExpandedBytes > s.Scope.ExpandedLimit || s.Seal.ExpandedBytes > s.Policy.WorkspaceBytes || len(s.Seal.Signature) != ed25519.SignatureSize || s.Version != VersionID(s.Seal) || s.Number == 0 || s.ContextRevision == 0 || s.PolicyRevision == 0 || s.RegistryGeneration == 0 || s.RegistrySpec == ([32]byte{}) || s.CreatedAt == 0 || s.CreatedAt > math.MaxInt64-s.Policy.Seconds {
		return ErrInvalid
	}
	if s.Commit != "" && (len(s.Commit) != 40 || strings.IndexFunc(s.Commit, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) >= 0) {
		return ErrInvalid
	}
	if _, err := s.OutputTags(); err != nil {
		return err
	}
	return nil
}
func (s JobSpec) Validate() error {
	if s.Shape() != nil || !s.Seal.Valid(s.Scope) {
		return ErrInvalid
	}
	return nil
}
func (s JobSpec) OutputRepository() string { return s.RegistryAuthority + "/" + s.Context.Repository }
func (s JobSpec) OutputTags() ([]string, error) {
	name, err := reference.ParseNormalizedNamed(s.OutputRepository())
	if err != nil || !reference.IsNameOnly(name) || name.Name() != s.OutputRepository() || reference.Domain(name) != s.RegistryAuthority {
		return nil, ErrInvalid
	}
	var out []string
	for _, rule := range s.Context.Tags {
		if strings.Contains(rule, "{commit}") && s.Commit == "" {
			return nil, ErrInvalid
		}
		tag := strings.ReplaceAll(strings.ReplaceAll(rule, "{version}", fmt.Sprint(s.Number)), "{commit}", s.Commit)
		n, err := reference.WithTag(name, tag)
		if err != nil || slices.Contains(out, n.String()) {
			return nil, ErrInvalid
		}
		out = append(out, n.String())
	}
	if len(out) == 0 {
		return nil, ErrInvalid
	}
	return out, nil
}
func (s JobSpec) Own() JobSpec {
	s.Context = s.Context.Own()
	s.Policy.Nodes = slices.Clone(s.Policy.Nodes)
	s.Policy.Platforms = slices.Clone(s.Policy.Platforms)
	s.Seal.Signature = slices.Clone(s.Seal.Signature)
	return s
}

type JobResult struct {
	Code, Image string
	Bytes       int64
}

func (r JobResult) Valid(s JobSpec) bool {
	if r.Code == "OK" {
		n, err := parseCanonical(r.Image)
		return err == nil && n.Name() == s.OutputRepository() && n.Digest().Algorithm().String() == "sha256" && r.Bytes > 0 && r.Bytes <= MaxExpandedBytes
	}
	switch r.Code {
	case "UNTRUSTED_BASE", "TIMEOUT", "SOURCE_FETCH", "BUILD_FAILED", "CANCELLED", "PERMISSION_REVOKED", "CONFLICT", "STORAGE_UNAVAILABLE":
		return r.Image == "" && r.Bytes == 0
	}
	return false
}

type JobClosure struct {
	Schema      uint8
	Job, Native [32]byte
	// Builder is the image ID the build container was created from. Empty
	// when no container was created.
	Builder   string `json:",omitempty"`
	Result    JobResult
	At        uint64
	Signature []byte
}

func JobClosureBytes(r JobClosure) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-imagebuild-job-closure-1\x00"), raw...)
}
func (c JobClosure) Valid(s JobSpec) bool {
	return c.Schema == 1 && (c.Builder == "" || nativeImageID(c.Builder)) && c.Job == s.Digest() && c.Native != ([32]byte{}) && c.At >= s.CreatedAt && c.At <= math.MaxInt64 && c.Result.Valid(s) && ed25519.Verify(s.Scope.Root.Key[:], JobClosureBytes(c), c.Signature)
}

type JobRun struct {
	Spec     JobSpec
	Revision uint64
	Phase    string
	Cancel   bool
	Inputs   []FrozenSource `json:",omitempty"`
	// Builder is the build container's image, resolved from the policy's
	// reference once at begin for this job only. BuilderLocal is set when
	// the registry did not answer and the node's last pulled copy was used.
	Builder      *FrozenSource `json:",omitempty"`
	BuilderLocal string        `json:",omitempty"`
	Closure      *JobClosure   `json:",omitempty"`
}

func (r JobRun) Terminal() bool { return r.Closure != nil }
func (r JobRun) Shape() error {
	if r.Spec.Shape() != nil || r.Revision == 0 || ValidateJobInputs(r.Spec, r.Inputs) != nil || r.Phase == "queued" && (len(r.Inputs) != 0 || r.Builder != nil) || validJobBuilder(r.Spec, r.Builder, r.BuilderLocal, false) != nil {
		return ErrInvalid
	}
	switch r.Phase {
	case "queued", "running", "unknown":
		if r.Closure != nil {
			return ErrInvalid
		}
	case "succeeded", "failed", "cancelled":
		if r.Closure == nil || r.Closure.Schema != 1 || r.Closure.Job != r.Spec.Digest() || r.Closure.Native == ([32]byte{}) || !r.Closure.Result.Valid(r.Spec) || r.Closure.At < r.Spec.CreatedAt || r.Closure.At > math.MaxInt64 || len(r.Closure.Signature) != ed25519.SignatureSize || r.Phase != jobFinalPhase(r.Closure.Result.Code) || r.Phase == "cancelled" && !r.Cancel {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func NewJob(s JobSpec) (JobRun, error) {
	if s.Validate() != nil {
		return JobRun{}, ErrInvalid
	}
	return JobRun{Spec: s.Own(), Revision: 1, Phase: "queued"}, nil
}
func (r JobRun) RequestCancel(expected uint64) (JobRun, error) {
	if r.Shape() != nil || r.Terminal() || r.Cancel || expected != r.Revision || r.Revision == math.MaxUint64 {
		return JobRun{}, ErrConflict
	}
	r.Cancel = true
	r.Revision++
	return r, nil
}
func (r JobRun) Begin(expected uint64, at uint64, inputs []FrozenSource, builder *FrozenSource, local string) (JobRun, error) {
	if r.Shape() != nil || r.Phase != "queued" || r.Cancel || expected != r.Revision || r.Revision == math.MaxUint64 || at < r.Spec.CreatedAt || at >= r.Spec.CreatedAt+r.Spec.Policy.Seconds || ValidateJobInputs(r.Spec, inputs) != nil || ValidateJobBuilder(r.Spec, builder, local) != nil {
		return JobRun{}, ErrConflict
	}
	r.Inputs = slices.Clone(inputs)
	b := *builder
	r.Builder, r.BuilderLocal = &b, local
	r.Phase = "running"
	r.Revision++
	return r, nil
}
func ValidateJobInputs(spec JobSpec, inputs []FrozenSource) error {
	if len(inputs) > 128 {
		return ErrInvalid
	}
	raw, _ := json.Marshal(inputs)
	if len(raw) > 16<<10 {
		return ErrInvalid
	}
	for _, input := range inputs {
		s := input.Source
		if !s.Valid() || s.Kind == BuilderKind || !slices.Contains(spec.Policy.Platforms, s.Platform) {
			return ErrInvalid
		}
	}
	_, err := SourcePolicy(inputs)
	return err
}
func (r JobRun) Uncertain(expected uint64) (JobRun, error) {
	if r.Shape() != nil || r.Phase != "running" || expected != r.Revision || r.Revision == math.MaxUint64 {
		return JobRun{}, ErrConflict
	}
	r.Phase = "unknown"
	r.Revision++
	return r, nil
}
func (r JobRun) Complete(expected uint64, closure JobClosure) (JobRun, error) {
	if r.Shape() != nil || r.Terminal() || expected != r.Revision || r.Revision == math.MaxUint64 || !closure.Valid(r.Spec) || r.Phase == "queued" && closure.Result.Code == "OK" || closure.Result.Code == "CANCELLED" && !r.Cancel {
		return JobRun{}, ErrConflict
	}
	closure.Signature = slices.Clone(closure.Signature)
	r.Closure = &closure
	r.Phase = jobFinalPhase(closure.Result.Code)
	r.Revision++
	return r, nil
}
func jobFinalPhase(code string) string {
	if code == "OK" {
		return "succeeded"
	}
	if code == "CANCELLED" {
		return "cancelled"
	}
	return "failed"
}
