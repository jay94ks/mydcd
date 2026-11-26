// SPDX-License-Identifier: Apache-2.0

package mydc

// REQ-56 fake internals (the Conn method is ProbeCD,
// fake_service_real.go): `cd-probe`, a read-only check that mydcd can read a Git
// source before CD is connected. Nothing is stored; the CD policy and
// candidate stay as they are. Credential is a server credential name, never
// a secret. Permission: the app's Deploy (in the fake: tenant manager).

const (
	CDProbeAuthFailed   = "auth-failed"
	CDProbeNoRepository = "no-repository"
	CDProbeNoBranch     = "no-branch"
	CDProbeNoFile       = "no-file"
	CDProbeNoCredential = "no-credential"
	CDProbeTimeout      = "timeout"
	CDProbeRateLimited  = "rate-limited"
)

type cdProbeRequest struct {
	Tenant, App string
	Repository  string // https URL, no user info
	Branch      string
	Path        string // relative file in the repository
	Credential  string `json:",omitempty"`
}

// cdProbeResult: Code "" = read; Commit is the branch head, Size the file's
// bytes, Node the server that read it. A failed read is a Code, not an
// error; permission and input errors are errors.
type cdProbeResult struct {
	Code   string `json:",omitempty"`
	Commit string `json:",omitempty"`
	Size   int64  `json:",omitempty"`
	Node   string `json:",omitempty"`
}
