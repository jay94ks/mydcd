// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// CDBlock is app.yaml `x-sfc.cd`, the app's CD policy as a person writes it.
// Deploying the app with the block turns CD on, changing it changes the
// policy, and deploying without it turns CD off. Values with one allowed
// setting today (runtime edits, queue limits, 30s fetch, 4MiB file) are not
// in the block; the server keeps them.
type CDBlock struct {
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

func cdError(field string) error { return inputError("INVALID_CD", "x-sfc.cd."+field) }

// UnmarshalYAML reads `x-sfc.cd` into the server's policy form, with defaults.
func (p *DeliveryDeclaration) UnmarshalYAML(n *yaml.Node) error {
	var b CDBlock
	if n.Kind != yaml.MappingNode || strictNode(n, &b) != nil {
		return inputError("INVALID_FIELD", "x-sfc.cd")
	}
	d, err := b.Declaration()
	if err != nil {
		return err
	}
	*p = d
	return nil
}

// MarshalYAML writes the policy back as `x-sfc.cd`.
func (p DeliveryDeclaration) MarshalYAML() (any, error) { return CDBlockOf(p), nil }

// CDBlockOf is the `x-sfc.cd` form of a stored policy (`sfcli cd show`).
func CDBlockOf(p DeliveryDeclaration) CDBlock {
	b := CDBlock{Repository: p.Source.Repository, Branch: p.Source.Ref, Path: p.Source.Path, Credential: p.Source.Credential, Prune: p.Sync.Prune, Poll: cdPollText(p.Poll), Sync: "manual", Drift: p.Sync.Drift}
	if p.Sync.Mode == "automatic" {
		b.Sync = "auto"
	}
	return b
}

// Declaration is the server's policy form of the block, with defaults.
func (b CDBlock) Declaration() (DeliveryDeclaration, error) {
	var p DeliveryDeclaration
	switch {
	case b.Repository == "":
		return p, cdError("repository")
	case b.Branch == "":
		return p, cdError("branch")
	case b.Path == "":
		return p, cdError("path")
	}
	p.Enabled = true
	p.Source.Kind, p.Source.Repository, p.Source.Ref, p.Source.Path, p.Source.Credential = "git", b.Repository, b.Branch, b.Path, b.Credential
	poll := time.Minute
	if b.Poll != "" {
		v, err := time.ParseDuration(b.Poll)
		if err != nil || v < time.Second || v > 24*time.Hour || v%time.Second != 0 {
			return p, cdError("poll")
		}
		poll = v
	}
	p.Poll = uint64(poll / time.Second)
	p.Limits.Fetch, p.Limits.Bytes = 30, 4<<20
	p.Limits.Queued, p.Limits.Active = 1, 1
	switch b.Sync {
	case "", "manual":
		p.Sync.Mode = "manual"
	case "auto":
		p.Sync.Mode = "automatic"
	default:
		return p, cdError("sync")
	}
	switch b.Drift {
	case "", "report":
		p.Sync.Drift = "report"
	case "reconcile":
		p.Sync.Drift = "reconcile"
	default:
		return p, cdError("drift")
	}
	p.Sync.Prune = b.Prune
	p.Runtime.Mode, p.Runtime.Expiry = "require-explicit-override", "manual-release"
	return p, nil
}

// cdPollText is a poll interval in seconds as the shortest whole unit (1m, 90s, 2h).
func cdPollText(seconds uint64) string {
	switch {
	case seconds != 0 && seconds%3600 == 0:
		return fmt.Sprintf("%dh", seconds/3600)
	case seconds != 0 && seconds%60 == 0:
		return fmt.Sprintf("%dm", seconds/60)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}
