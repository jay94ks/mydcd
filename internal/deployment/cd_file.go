// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// CDFile is cd.yaml, the CD policy of one app as a person writes it
// (`mydc cd set APP -f cd.yaml`). It is the desired state only; the server
// keeps the policy, its revision and the app it belongs to. Values that have
// one allowed setting today (runtime edits, queue limits) are not in the
// file; the server keeps their defaults (30s fetch timeout, 4MiB file).
type CDFile struct {
	Version    int    `yaml:"version" json:"version"`
	Repository string `yaml:"repository" json:"repository"`
	Branch     string `yaml:"branch" json:"branch"`
	Path       string `yaml:"path" json:"path"`
	Credential string `yaml:"credential,omitempty" json:"credential,omitempty"`
	// Poll is how often the branch is checked, such as 1m (default 1m).
	Poll string `yaml:"poll,omitempty" json:"poll,omitempty"`
	// Sync is manual (a person approves each new commit) or auto.
	Sync string `yaml:"sync,omitempty" json:"sync,omitempty"`
	// Drift is report (show changes made outside Git) or reconcile (undo them).
	Drift string `yaml:"drift,omitempty" json:"drift,omitempty"`
	// Prune removes services that disappear from the file.
	Prune bool `yaml:"prune,omitempty" json:"prune,omitempty"`
}

// ErrCDFile is a cd.yaml that cannot be read or does not describe a policy.
var ErrCDFile = errors.New("invalid cd.yaml")

func cdFileError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCDFile, fmt.Sprintf(format, args...))
}

// ParseCDFile reads cd.yaml into the server's policy form, with defaults.
func ParseCDFile(raw []byte) (DeliveryDeclaration, error) {
	var f CDFile
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if err := d.Decode(&f); err != nil {
		return DeliveryDeclaration{}, cdFileError("%v", err)
	}
	return f.Declaration()
}

// Declaration converts the file to the server's policy form.
func (f CDFile) Declaration() (DeliveryDeclaration, error) {
	var p DeliveryDeclaration
	if f.Version != 1 {
		return p, cdFileError("the first line must be 'version: 1'")
	}
	if f.Repository == "" || f.Branch == "" || f.Path == "" {
		return p, cdFileError("repository, branch and path are required")
	}
	p.Enabled = true
	p.Source.Kind, p.Source.Repository, p.Source.Ref, p.Source.Path, p.Source.Credential = "git", f.Repository, f.Branch, f.Path, f.Credential
	poll, err := cdDuration(f.Poll, time.Minute, time.Second, 24*time.Hour, "poll")
	if err != nil {
		return p, err
	}
	p.Poll = uint64(poll / time.Second)
	p.Limits.Fetch, p.Limits.Bytes = 30, 4<<20
	p.Limits.Queued, p.Limits.Active = 1, 1
	switch f.Sync {
	case "", "manual":
		p.Sync.Mode = "manual"
	case "auto":
		p.Sync.Mode = "automatic"
	default:
		return p, cdFileError("sync must be manual or auto")
	}
	switch f.Drift {
	case "", "report":
		p.Sync.Drift = "report"
	case "reconcile":
		p.Sync.Drift = "reconcile"
	default:
		return p, cdFileError("drift must be report or reconcile")
	}
	p.Sync.Prune = f.Prune
	p.Runtime.Mode, p.Runtime.Expiry = "require-explicit-override", "manual-release"
	return p, nil
}

// CDFileOf is the cd.yaml form of a stored policy (`mydc cd show -o yaml`
// prints it, so it can be edited and set again).
func CDFileOf(p DeliveryDeclaration) CDFile {
	f := CDFile{Version: 1, Repository: p.Source.Repository, Branch: p.Source.Ref, Path: p.Source.Path, Credential: p.Source.Credential, Prune: p.Sync.Prune}
	f.Poll = (time.Duration(p.Poll) * time.Second).String()
	f.Sync = "manual"
	if p.Sync.Mode == "automatic" {
		f.Sync = "auto"
	}
	f.Drift = p.Sync.Drift
	return f
}

func cdDuration(text string, def, low, high time.Duration, name string) (time.Duration, error) {
	if text == "" {
		return def, nil
	}
	v, err := time.ParseDuration(text)
	if err != nil || v < low || v > high || v%time.Second != 0 {
		return 0, cdFileError("%s must be whole seconds from %s to %s, such as %s", name, low, high, def)
	}
	return v, nil
}
