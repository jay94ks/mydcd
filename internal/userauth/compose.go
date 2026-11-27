// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/sha256"
	"fmt"
	"os"

	"bytes"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
)

// ComposeIntent freezes the public artifact and inventory CAS before the first
// management send. Individual signed mutations use the existing operation
// journal, preserving original credentials/CAS/IDs across explicit resume.
type ComposeIntent struct {
	Standalone *control.StandaloneDefinition `json:",omitempty"`
	Target     *[32]byte                     `json:",omitempty"`
	Move       *control.VolumeMoveBegin      `json:",omitempty"`
	Schema     uint8
	Profile    [32]byte
	User, ID   string
	Scope      deployment.AppScope
	Expected   uint64
	Epoch      uint64
	Length     int
	Digest     [32]byte
	Artifact   []byte `json:"-"`
}
type composePart struct{ Data []byte }

func composeIntentActor(user string, move *control.VolumeMoveBegin) string {
	if move != nil && move.App != nil && move.App.CD != nil {
		return move.App.CD.Principal
	}
	return user
}

func composeRoot(home string, c Client, user, id string, create bool) (*os.Root, error) {
	if !safeID(id) {
		return nil, ErrPrivateState
	}
	r, err := operationRoot(home, c, user, create)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"compose", operationName(id)[:64]} {
		if !create {
			if _, err := r.Lstat(name); os.IsNotExist(err) {
				_ = r.Close()
				return nil, ErrOperationMissing
			}
		}
		next, err := descend(r, name, create)
		_ = r.Close()
		if err != nil {
			return nil, err
		}
		r = next
	}
	return r, nil
}
func readCompose(root *os.Root, c Client, current access.Session, id string) (ComposeIntent, error) {
	var intent ComposeIntent
	if readPrivate(root, "intent.json", &intent) != nil || intent.Schema != 1 || intent.Epoch == 0 || intent.Profile != c.JournalProfile() || intent.User != current.User || intent.ID != id || intent.Scope.Cluster != c.Cluster || intent.Scope.Actor != composeIntentActor(current.User, intent.Move) || intent.Length < 1 || intent.Length > deployment.ArtifactMaxBytes {
		return ComposeIntent{}, ErrPrivateState
	}
	if !validComposeTarget(intent.Scope, intent.Expected, intent.Move, intent.Target) {
		return ComposeIntent{}, ErrPrivateState
	}
	for index := 0; index < (intent.Length+deployment.ArtifactPartBytes-1)/deployment.ArtifactPartBytes; index++ {
		var part composePart
		if readPrivate(root, fmt.Sprintf("part-%03d.json", index), &part) != nil || len(part.Data) != min(deployment.ArtifactPartBytes, intent.Length-index*deployment.ArtifactPartBytes) {
			return ComposeIntent{}, ErrPrivateState
		}
		intent.Artifact = append(intent.Artifact, part.Data...)
	}
	plan, err := deployment.DecodeBlueprint(intent.Artifact)
	if err != nil || sha256.Sum256(intent.Artifact) != intent.Digest || plan.Scope() != intent.Scope || (intent.Standalone == nil) != (plan.StandaloneName() == "") || intent.Standalone != nil && intent.Standalone.Name != plan.StandaloneName() {
		return ComposeIntent{}, ErrPrivateState
	}
	if intent.Move != nil {
		if intent.Move.ID != intent.ID {
			return ComposeIntent{}, ErrPrivateState
		}
		raw, _ := json.Marshal(control.AppMovePlan{Schema: 1, Expected: intent.Expected, Epoch: intent.Epoch, Begin: *intent.Move, Artifact: intent.Artifact})
		if _, err := control.DecodeAppMovePlan(raw); err != nil {
			return ComposeIntent{}, ErrPrivateState
		}
	}
	return intent, nil
}
func LoadCompose(home string, c Client, current access.Session, id string) (ComposeIntent, error) {
	if c.Verify(current) != nil {
		return ComposeIntent{}, ErrPrivateState
	}
	r, err := composeRoot(home, c, current.User, id, false)
	if err != nil {
		return ComposeIntent{}, err
	}
	defer r.Close()
	if _, err = r.Lstat("intent.json"); os.IsNotExist(err) {
		return ComposeIntent{}, ErrOperationMissing
	}
	return readCompose(r, c, current, id)
}
func StageCompose(home string, c Client, current access.Session, id string, artifact []byte, expected, epoch uint64) (ComposeIntent, error) {
	return stageCompose(home, c, current, id, artifact, expected, epoch, nil, nil)
}

func StageComposeTarget(home string, c Client, current access.Session, id string, artifact []byte, expected, epoch uint64, target [32]byte) (ComposeIntent, error) {
	if target == ([32]byte{}) {
		return ComposeIntent{}, ErrPrivateState
	}
	return stageCompose(home, c, current, id, artifact, expected, epoch, nil, &target)
}

func validComposeTarget(scope deployment.AppScope, expected uint64, move *control.VolumeMoveBegin, target *[32]byte) bool {
	return target == nil || move == nil && *target != ([32]byte{}) &&
		(expected > 0 || *target == control.AppCreateTarget(scope.Cluster, scope.Tenant, scope.App, scope.Deployment))
}
func StageComposeMove(home string, c Client, current access.Session, plan control.AppMovePlan) (ComposeIntent, error) {
	raw, err := json.Marshal(plan)
	if err != nil {
		return ComposeIntent{}, err
	}
	frozen, err := control.DecodeAppMovePlan(raw)
	if err != nil {
		return ComposeIntent{}, err
	}
	return stageCompose(home, c, current, frozen.Begin.ID, frozen.Artifact, frozen.Expected, frozen.Epoch, &frozen.Begin, nil)
}
func StageStandalone(home string, c Client, current access.Session, id string, artifact []byte, expected, epoch uint64, definition control.StandaloneDefinition) (ComposeIntent, error) {
	return stageCompose(home, c, current, id, artifact, expected, epoch, nil, nil, &definition)
}

// StageStandaloneTarget freezes the management target with the original input.
// Loading an older intent never upgrades its absent target or signed mode.
func StageStandaloneTarget(home string, c Client, current access.Session, id string, artifact []byte, expected, epoch uint64, definition control.StandaloneDefinition, target [32]byte) (ComposeIntent, error) {
	if target == ([32]byte{}) {
		return ComposeIntent{}, ErrPrivateState
	}
	return stageCompose(home, c, current, id, artifact, expected, epoch, nil, &target, &definition)
}

func stageCompose(home string, c Client, current access.Session, id string, artifact []byte, expected, epoch uint64, move *control.VolumeMoveBegin, target *[32]byte, standalone ...*control.StandaloneDefinition) (ComposeIntent, error) {
	if len(standalone) > 1 {
		return ComposeIntent{}, ErrPrivateState
	}
	var definition *control.StandaloneDefinition
	if len(standalone) == 1 {
		definition = standalone[0]
	}
	if c.Verify(current) != nil || epoch == 0 {
		return ComposeIntent{}, ErrPrivateState
	}
	plan, err := deployment.DecodeBlueprint(artifact)
	if err != nil || len(artifact) > deployment.ArtifactMaxBytes {
		return ComposeIntent{}, ErrPrivateState
	}
	if (definition == nil) != (plan.StandaloneName() == "") || definition != nil && definition.Name != plan.StandaloneName() {
		return ComposeIntent{}, ErrPrivateState
	}
	scope := plan.Scope()
	if scope.Cluster != c.Cluster || scope.Actor != composeIntentActor(current.User, move) {
		return ComposeIntent{}, ErrPrivateState
	}
	if !validComposeTarget(scope, expected, move, target) {
		return ComposeIntent{}, ErrPrivateState
	}
	r, err := composeRoot(home, c, current.User, id, true)
	if err != nil {
		return ComposeIntent{}, err
	}
	defer r.Close()
	unlock, err := lockProfile(r)
	if err != nil {
		return ComposeIntent{}, err
	}
	defer unlock()
	if _, sourceErr := r.Lstat("sources.json"); sourceErr == nil {
		if move != nil {
			return ComposeIntent{}, ErrPrivateState
		}
		parent, err := readComposeSources(r, c, current.User, id)
		if err != nil || checkPreparedComposePlan(home, c, current, parent, plan) != nil {
			return ComposeIntent{}, ErrPrivateState
		}
	} else if !os.IsNotExist(sourceErr) {
		return ComposeIntent{}, ErrPrivateState
	}
	if _, err = r.Lstat("intent.json"); err == nil {
		i, err := readCompose(r, c, current, id)
		if err != nil || i.Digest != sha256.Sum256(artifact) || i.Expected != expected || i.Epoch != epoch || !sameComposeMove(i.Move, move) || !sameStandaloneDefinition(i.Standalone, definition) || (i.Target == nil) != (target == nil) || i.Target != nil && *i.Target != *target {
			return ComposeIntent{}, ErrPrivateState
		}
		return i, nil
	} else if !os.IsNotExist(err) {
		return ComposeIntent{}, ErrPrivateState
	}
	i := ComposeIntent{Standalone: definition, Move: move, Schema: 1, Profile: c.JournalProfile(), User: current.User, ID: id, Scope: scope, Expected: expected, Epoch: epoch, Length: len(artifact), Digest: sha256.Sum256(artifact), Artifact: append([]byte(nil), artifact...)}
	if target != nil {
		value := *target
		i.Target = &value
	}
	for index, start := 0, 0; start < len(artifact); index, start = index+1, start+deployment.ArtifactPartBytes {
		if err = writePrivate(r, fmt.Sprintf("part-%03d.json", index), composePart{artifact[start:min(len(artifact), start+deployment.ArtifactPartBytes)]}); err != nil {
			return ComposeIntent{}, err
		}
	}
	if err = writePrivate(r, "intent.json", i); err != nil {
		return ComposeIntent{}, err
	}
	return i, nil
}

func sameComposeMove(a, b *control.VolumeMoveBegin) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

func sameStandaloneDefinition(a, b *control.StandaloneDefinition) bool {
	ar, _ := json.Marshal(a)
	br, _ := json.Marshal(b)
	return bytes.Equal(ar, br)
}
