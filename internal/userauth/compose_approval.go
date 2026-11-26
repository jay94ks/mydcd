// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/secrets"
)

// ComposeApprovalAttempt retains public original identity/outcome only. Neither
// the password, a verifier, nor a digest of private input is written here.
type ComposeApprovalAttempt struct {
	Selection              *control.AppApprovalSelection `json:",omitempty"`
	Schema                 uint8
	Profile                [32]byte
	User, Compose, Outcome string
	Origin                 [32]byte
	Target                 secrets.Target
	Approver               config.Peer
}

func composeApprovalName(a ComposeApprovalAttempt) string {
	if a.Selection != nil {
		raw, _ := json.Marshal(struct {
			Origin    [32]byte
			Target    secrets.Target
			Key       string
			Selection *control.AppApprovalSelection
		}{a.Origin, a.Target, a.Approver.Key, a.Selection})
		return fmt.Sprintf("approval-%x.json", sha256.Sum256(raw))
	}
	raw, _ := json.Marshal(struct {
		Origin [32]byte
		Target secrets.Target
		Key    string
	}{a.Origin, a.Target, a.Approver.Key})
	return fmt.Sprintf("approval-%x.json", sha256.Sum256(raw))
}

func composeApproval(c Client, session access.Session, id string, origin control.UserOperation, target secrets.Target, peer config.Peer, selections ...*control.AppApprovalSelection) (ComposeApprovalAttempt, error) {
	var selection *control.AppApprovalSelection
	if len(selections) > 1 {
		return ComposeApprovalAttempt{}, ErrPrivateState
	}
	if len(selections) == 1 {
		selection = selections[0]
	}
	if selection != nil && (origin.Change.Action != "begin-app" || !selection.Valid()) {
		return ComposeApprovalAttempt{}, ErrPrivateState
	}
	if selection != nil {
		owned := *selection
		if selection.Candidate != nil {
			candidate := *selection.Candidate
			owned.Candidate = &candidate
		}
		selection = &owned
	}
	var tenant, app, deployment, operation string
	if origin.Change.Action == "begin-volume-move" {
		var q control.VolumeMoveBegin
		if json.Unmarshal(origin.Change.Payload, &q) != nil || q.App == nil || q.App.Target == nil || q.App.Target.Upload != id || q.App.Target.Operation != id || q.Scope.Cluster != c.Cluster {
			return ComposeApprovalAttempt{}, ErrPrivateState
		}
		tenant, app, deployment, operation = q.Scope.Tenant, q.Scope.App, target.Deployment, q.App.Target.Operation
	} else if origin.Change.Action == "begin-app" || origin.Change.Action == "standalone-up" {
		var begin control.AppBegin
		if json.Unmarshal(origin.Change.Payload, &begin) != nil {
			return ComposeApprovalAttempt{}, ErrPrivateState
		}
		if origin.Change.Action == "standalone-up" {
			d := begin.Standalone
			canonical, err := json.Marshal(begin)
			if err != nil || !bytes.Equal(canonical, origin.Change.Payload) || d == nil || !lifecycle.ValidID(d.Name) || d.Mode != "" && d.Mode != "shell" && d.Mode != "entrypoint" || d.Lifetime != "" && d.Lifetime != "temp" && d.Lifetime != "fixed" || begin.Upload != id || target.Purpose != "" {
				return ComposeApprovalAttempt{}, ErrPrivateState
			}
			// A pin can rename the public name while retaining the original
			// internal scope. Match the signed scope to the approval target
			// below; current name/owner admission remains the server's check.
		}
		tenant, app, deployment, operation = begin.Tenant, begin.App, begin.Deployment, begin.Operation
	} else if origin.Change.Action == "bind-external-registry" {
		var q control.ExternalRegistryBind
		if selection != nil || target.Purpose != secrets.PurposeRegistrySource || json.Unmarshal(origin.Change.Payload, &q) != nil || q.Definition == ([32]byte{}) || q.Node == "" || id != origin.RequestID {
			return ComposeApprovalAttempt{}, ErrPrivateState
		}
		scope := control.ExternalRegistryScope(q.Tenant, q.ID)
		tenant, app, deployment, operation = q.Tenant, scope, scope, origin.RequestID
	} else if origin.Change.Action == "begin-image-build" {
		var q control.ImageBuildJobStart
		if selection != nil || target.Purpose != secrets.PurposeImageBuild || json.Unmarshal(origin.Change.Payload, &q) != nil || q.Tenant == "" || q.Context == "" || q.ID == "" || q.Version == ([32]byte{}) || q.Snapshot == ([32]byte{}) || q.At == 0 || origin.Change.Expected != 0 || id != origin.RequestID {
			return ComposeApprovalAttempt{}, ErrPrivateState
		}
		tenant, app, deployment, operation = q.Tenant, control.ImageBuildSecretScope(q.Tenant, q.Context), q.ID, origin.RequestID
	} else {
		return ComposeApprovalAttempt{}, ErrPrivateState
	}
	if c.Verify(session) != nil || origin.VerifyOriginal(c.Cluster) != nil || origin.Session.User != session.User || operation != id || tenant != target.Tenant || app != target.App || deployment != target.Deployment || target.User != session.User || target.RequesterKey != origin.Session.Key || target.Cluster != c.Cluster || target.ApprovalID == "" || peer.ID == "" || peer.Key == "" || peer.Endpoint == "" {
		return ComposeApprovalAttempt{}, ErrPrivateState
	}
	cmd, err := origin.Command()
	if err != nil {
		return ComposeApprovalAttempt{}, err
	}
	raw, _ := json.Marshal(cmd)
	return ComposeApprovalAttempt{Schema: 1, Profile: c.JournalProfile(), User: session.User, Compose: id, Outcome: "pending", Origin: sha256.Sum256(raw), Target: target, Approver: peer, Selection: selection}, nil
}

func readComposeApproval(root *os.Root, name string, want ComposeApprovalAttempt) (ComposeApprovalAttempt, error) {
	var old ComposeApprovalAttempt
	if readPrivate(root, name, &old) != nil || old.Schema != 1 || old.Profile != want.Profile || old.User != want.User || old.Compose != want.Compose || old.Origin != want.Origin || old.Selection != nil && !old.Selection.Valid() || composeApprovalName(old) != name || old.Outcome != "pending" && old.Outcome != "confirmed" && old.Outcome != "rejected" && old.Outcome != "not-sent" {
		return old, ErrPrivateState
	}
	return old, nil
}

func pendingComposeApproval(root *os.Root, want ComposeApprovalAttempt) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	names, err := dir.Readdirnames(-1)
	_ = dir.Close()
	if err != nil {
		return err
	}
	count := 0
	for _, name := range names {
		if !strings.HasPrefix(name, "approval-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		count++
		old, err := readComposeApproval(root, name, want)
		if err != nil {
			return err
		}
		if old.Outcome == "pending" && old.Target.Realm == want.Target.Realm && old.Target.Group == want.Target.Group && name != composeApprovalName(want) {
			return ErrApprovalUnknown
		}
	}
	if count >= 4096 {
		return ErrPrivateState
	}
	return nil
}

func LoadComposeApproval(home string, c Client, session access.Session, id string, origin control.UserOperation, target secrets.Target, peer config.Peer, selections ...*control.AppApprovalSelection) (ComposeApprovalAttempt, error) {
	want, err := composeApproval(c, session, id, origin, target, peer, selections...)
	if err != nil {
		return want, err
	}
	root, err := composeRoot(home, c, session.User, id, false)
	if err != nil {
		return want, err
	}
	defer root.Close()
	name := composeApprovalName(want)
	if _, err = root.Lstat(name); os.IsNotExist(err) {
		if err := pendingComposeApproval(root, want); err != nil {
			return want, err
		}
		return want, ErrOperationMissing
	}
	return readComposeApproval(root, name, want)
}

// PrepareComposeApprovals opens only the existing approval journal namespace.
// CD, image-build and registry-source clients need no local Compose artifact.
func PrepareComposeApprovals(home string, c Client, session access.Session, id string) error {
	if c.Verify(session) != nil {
		return ErrPrivateState
	}
	root, err := composeRoot(home, c, session.User, id, true)
	if err != nil {
		return err
	}
	return root.Close()
}

// StageComposeApproval is the durable BEFORE-SEND boundary for private input.
func StageComposeApproval(home string, c Client, session access.Session, want ComposeApprovalAttempt) error {
	if c.Verify(session) != nil || want.Schema != 1 || want.Profile != c.JournalProfile() || want.User != session.User || want.Outcome != "pending" {
		return ErrPrivateState
	}
	root, err := composeRoot(home, c, session.User, want.Compose, false)
	if err != nil {
		return err
	}
	defer root.Close()
	unlock, err := lockProfile(root)
	if err != nil {
		return err
	}
	defer unlock()
	if err = pendingComposeApproval(root, want); err != nil {
		return err
	}
	name := composeApprovalName(want)
	if _, err := root.Lstat(name); err == nil {
		old, err := readComposeApproval(root, name, want)
		if err != nil || old.Outcome == "confirmed" {
			return ErrPrivateState
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return writePrivate(root, name, want)
}

func RecordComposeApproval(home string, c Client, session access.Session, want ComposeApprovalAttempt, outcome string) error {
	if c.Verify(session) != nil || want.Profile != c.JournalProfile() || want.User != session.User || outcome != "confirmed" && outcome != "rejected" && outcome != "not-sent" {
		return ErrPrivateState
	}
	root, err := composeRoot(home, c, session.User, want.Compose, false)
	if err != nil {
		return err
	}
	defer root.Close()
	unlock, err := lockProfile(root)
	if err != nil {
		return err
	}
	defer unlock()
	old, err := readComposeApproval(root, composeApprovalName(want), want)
	if err != nil {
		return err
	}
	left, _ := json.Marshal(old.Target)
	right, _ := json.Marshal(want.Target)
	if !bytes.Equal(left, right) || old.Approver.Key != want.Approver.Key || old.Outcome != "pending" && old.Outcome != outcome {
		return ErrPrivateState
	}
	old.Outcome = outcome
	return writePrivate(root, composeApprovalName(want), old)
}
