// SPDX-License-Identifier: Apache-2.0

package mydc

// The fake's build world model that the real-contract views
// (image_builds.go) are made from: fixtures, contexts, jobs and cache. No
// Conn method takes or returns these types.
// Secret values never appear: build secrets and secret build arguments are
// vault references only.

// Action names; the payloads are the real control types (image_builds.go,
// fake_build_zip_real.go).
const (
	ActionPutBuildContext     = "put-build-context"
	ActionDeleteBuildContext  = "delete-build-context"
	ActionDeleteBuildVersion  = "delete-build-version"
	ActionPruneBuildCache     = "prune-build-cache"
	ActionBeginBuildZipUpload = "begin-build-zip-upload"
	ActionPutBuildZipPart     = "put-build-zip-part"
	ActionUploadBuildZip      = "upload-build-zip"
	ActionAbortBuildZipUpload = "abort-build-zip-upload"
)

// Context kinds.
const (
	BuildUpload = "upload"
	BuildGit    = "git"
	BuildInline = "inline"
)

// BuildPolicy: the fake's policy model (Fixture.BuildPolicies); the real
// view is imagebuild.Policy. Builder is the fixed-digest builder image.
type BuildPolicy struct {
	Tenant         string
	Revision       uint64
	Nodes          []string
	Concurrent     int
	TimeoutSeconds int
	CPUs           float64
	MemoryBytes    uint64
	ScratchBytes   uint64
	CacheBytes     uint64
	Registry       string // result registry (built-in)
	Platforms      []string
	Builder        string `json:",omitempty"` // read only
}

type BuildGitSource struct {
	Repository, Ref   string
	Folder            string `json:",omitempty"` // context folder
	CredentialProfile string `json:",omitempty"`
	AutoBuild         bool   // build on a new commit
	Commit            string `json:",omitempty"` // read: last fetched commit
}

// BuildArg: a plain build argument (Value), or a secret one whose value
// the build reads from the vault (Secret) and that no payload, record,
// digest or log ever holds.
type BuildArg struct {
	Name   string
	Value  string          `json:",omitempty"`
	Secret *BuildSecretRef `json:",omitempty"`
}

// BuildSecretRef: a vault key in the tenant realm.
type BuildSecretRef struct {
	Realm, Object, Key string
}

// BuildSecret: a vault value mounted only while the build runs (RUN
// --mount=type=secret,id=ID).
type BuildSecret struct {
	ID            string
	Realm, Object string
	Key           string
}

// BuildContext: a context in the fake's model. Version is the newest
// content version (0 = none yet).
type BuildContext struct {
	Tenant, ID string
	Name       string
	Kind       string
	Revision   uint64
	Version    uint64
	Versions   []uint64        `json:",omitempty"` // kept versions
	Git        *BuildGitSource `json:",omitempty"`
	Dockerfile string          // path in the context
	Args       []BuildArg      `json:",omitempty"`
	Secrets    []BuildSecret   `json:",omitempty"`
	Repository string          // result repository in the built-in registry
	TagRule    string          // e.g. "{version}", "{commit}", "latest"
	Platforms  []string        `json:",omitempty"`
}

// Build statuses and failure codes.
const (
	BuildQueued    = "queued"
	BuildRunning   = "running"
	BuildSucceeded = "succeeded"
	BuildFailed    = "failed"
	BuildCanceled  = "canceled"

	BuildUntrustedBase = "UNTRUSTED_BASE"
	BuildTimeout       = "TIMEOUT"
	BuildSourceFetch   = "SOURCE_FETCH"
	BuildBuildFailed   = "BUILD_FAILED"
)

type BuildStep struct {
	Name       string
	Status     string
	StartedAt  int64 `json:",omitempty"`
	FinishedAt int64 `json:",omitempty"`
}

// Build: a job in the fake's model.
type Build struct {
	Tenant, ID, Context string
	ContextVersion      uint64
	Commit              string `json:",omitempty"`
	Node                string
	Status              string
	Code                string `json:",omitempty"`
	Steps               []BuildStep
	Image               string `json:",omitempty"` // repository:tag pushed
	Digest              string `json:",omitempty"`
	Bytes               uint64 `json:",omitempty"`
	Submitter           string
	StartedAt           int64
	FinishedAt          int64 `json:",omitempty"`
}

// Build cache kinds.
const (
	BuildCacheExec   = "exec"   // RUN steps
	BuildCacheBase   = "base"   // FROM images
	BuildCacheMount  = "mount"  // cache mounts
	BuildCacheSource = "source" // sources / contexts
)

// BuildCachePolicy: the policy's cleanup in the fake's model. Prune when
// use passes MaxPercent of the limit, and entries unused for IdleDays
// (0 = off).
type BuildCachePolicy struct {
	Tenant     string `json:",omitempty"`
	MaxPercent int
	IdleDays   int
}

type BuildCacheEntry struct {
	ID       string
	Node     string
	Kind     string
	Summary  string
	Contexts []string
	Bytes    uint64
	LastUsed int64
	InUse    bool // a running build uses it: cannot be pruned
}
