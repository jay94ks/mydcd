// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/workload"
)

// sfev.sock: a service that lists `x-sfc.secrets.socket` reads those sources
// over a per-container Unix socket instead of files (design:
// devel/proposals/sfev-sock.md). Its approval is a separate signed purpose,
// and its grant a separate consumer with its own generation, so a new secret
// revision renews the grant without replacing the container.
const (
	// SecretSocketDir is where sfcd binds the socket directory in the
	// container. A service with a socket may mount nothing over it.
	SecretSocketDir = workload.SecretSocketTarget
	// SecretSocketPath is the socket in the container.
	SecretSocketPath = workload.SecretSocketPath
	// SecretSocketEnv names the socket in the container's environment.
	SecretSocketEnv = workload.SecretSocketEnv

	maxSocketSources = 64
)

// SocketConsumer is the sfev grant's consumer for a task consumer. It is
// distinct from the file/env consumer so the two grants renew separately.
func SocketConsumer(taskConsumer string) string {
	hash := sha256.Sum256(append([]byte("sfc-secret-socket-consumer-1\x00"), []byte(taskConsumer)...))
	return "sfev-" + hex.EncodeToString(hash[:24])
}

// SocketMetadata is a service's sfev.sock read recipe: purpose sfev, the
// socket sources in override order, nothing projected. ok is false when the
// service has no socket. Like InputMetadata it has no consumer or
// generation and is not a reservation or a permit.
func (b Blueprint) SocketMetadata(service string, requester [32]byte) (Needs, bool, error) {
	n, ok, err := b.socketMetadata(service, requester)
	return ownNeeds(n), ok, err
}

func (b Blueprint) socketMetadata(service string, requester [32]byte) (Needs, bool, error) {
	s, logical, err := b.taskInput(service)
	if err != nil || b.d.Schema != 1 {
		return Needs{}, false, ErrInputs
	}
	if len(s.Sfc.Socket) == 0 {
		return Needs{}, false, nil
	}
	var owner [32]byte
	for _, step := range b.d.Steps {
		if step.Kind == "task" && step.Key == ResourceKey("task", b.d.Tenant, b.d.App, service) {
			owner = step.Owner
			break
		}
	}
	n := Needs{Use: secrets.Use{Purpose: secrets.PurposeSecretSocket, Tenant: b.d.Tenant, User: b.d.Actor, App: b.d.App, Deployment: b.d.Deployment, Service: logical, Node: s.Sfc.Node, NodeKey: owner, RequesterKey: requester}}
	if s.Sfc.Instance != nil {
		instance := *s.Sfc.Instance
		n.Instance = &instance
	}
	for _, source := range resolveSelectors(b.d.Input, b.d.Tenant, s.Sfc.Socket) {
		if !slices.Contains(n.Sources, source) {
			n.Sources = append(n.Sources, source)
		}
	}
	if !validSocketMetadata(n) {
		return Needs{}, false, ErrInputs
	}
	return n, true, nil
}

// validSocketMetadata is validInputMetadata's rule for an sfev read: the
// same identity, at least one source, and nothing to project or mount.
func validSocketMetadata(n Needs) bool {
	if n.Use.Purpose != secrets.PurposeSecretSocket || len(n.Sources) == 0 || len(n.Sources) > maxSocketSources || len(n.RegistrySources) != 0 || len(n.Files) != 0 || len(n.Volumes) != 0 || len(n.FixedVolumes) != 0 || n.Lifecycle != nil || len(n.ResourceKeys) != 0 {
		return false
	}
	n.Use.Purpose = ""
	return validInputMetadata(n)
}

func (b *Blueprint) freezeSocketRevisions(c Compose, ctx PlanningContext) {
	if ctx.SecretRevisions == nil {
		return
	}
	for _, name := range mapKeys(c.Services) {
		s := c.Services[name]
		if len(s.Sfc.Socket) == 0 {
			continue
		}
		if b.d.SocketRevisions == nil {
			b.d.SocketRevisions = map[string]string{}
		}
		b.d.SocketRevisions[name] = ctx.SecretRevisions(resolveSelectors(c, c.Sfc.Tenant, s.Sfc.Socket))
	}
}

func validSocketRevisions(d blueprintRecord) bool {
	for name, digest := range d.SocketRevisions {
		s, ok := d.Input.Services[name]
		if !ok || len(s.Sfc.Socket) == 0 || digest == "" || len(digest) > 128 {
			return false
		}
	}
	return true
}

// TaskSecretSocketRuntimeUpdate reports whether a Task's next goal differs
// from its committed original only in its sfev.sock source revisions: the
// secrets it reads over the socket got new values and nothing else changed.
// Jay (2026-11-28 15:17 KST): that renews the socket's approval in place (a
// new sfev grant generation, the A2 record updated, `changed` sent on the
// open connection) instead of replacing the container. Any other
// difference, including the socket source list itself, returns false.
//
// It is a judgment input for Inventory.Changes, not a mutation grant.
func TaskSecretSocketRuntimeUpdate(claim Claim, step Step) bool {
	if claim.Removed || claim.Retained || claim.Result.Code != state.Applied || claim.Step.Kind != "task" || step.Kind != "task" || claim.Step.Key != step.Key || claim.Step.Node != step.Node || claim.Step.Owner != step.Owner || !bytes.Equal(goal(claim.Step.Dependencies), goal(step.Dependencies)) || !slices.Equal(claim.Step.Identity, step.Identity) || !bytes.Equal(goal(claim.Step.Activation), goal(step.Activation)) {
		return false
	}
	var original GoalCommand
	if json.Unmarshal([]byte(claim.Command.Value), &original) != nil {
		return false
	}
	return taskSocketOnly(original, step)
}

// taskSocketOnly is TaskSecretSocketRuntimeUpdate over the committed goal
// alone, for the planner's stable references (annotateStable).
func taskSocketOnly(original GoalCommand, step Step) bool {
	var before, after ComposeService
	if step.Kind != "task" || original.Kind != "task" || original.Node != step.Node || original.Owner != step.Owner || original.Lifecycle != nil || json.Unmarshal(original.Config, &before) != nil || json.Unmarshal(step.Goal, &after) != nil {
		return false
	}
	if len(after.Sfc.Socket) == 0 || before.SocketRevisions == after.SocketRevisions {
		return false
	}
	before.SocketRevisions, after.SocketRevisions = "", ""
	return bytes.Equal(goal(before), goal(after))
}

func (c Compose) hasSecretSocket() bool {
	for _, s := range c.Services {
		if len(s.Sfc.Socket) != 0 {
			return true
		}
	}
	return false
}

// SocketNeeds is a task's sfev.sock read in its Binding. Generation counts
// approval renewals of this task generation, from 1.
type SocketNeeds struct {
	Sources    []Source
	Generation uint64
}

func validSocketNeeds(s SocketNeeds, tenant string) bool {
	if s.Generation == 0 || len(s.Sources) == 0 || len(s.Sources) > maxSocketSources {
		return false
	}
	for i, source := range s.Sources {
		if !identifier(source.Object) || source.Realm != "" && source.Realm != tenant || source.Shared || slices.Contains(s.Sources[:i], source) {
			return false
		}
	}
	return true
}

// socketInputNeeds is a Binding's sfev grant group: purpose sfev, the
// socket sources, a consumer of its own per task generation and the renewal
// count as generation. Without a socket it has no sources and no grant.
func socketInputNeeds(n Needs) Needs {
	out := Needs{Consumer: SocketConsumer(n.Consumer + "/" + strconv.FormatUint(n.Generation, 10)), Use: n.Use}
	out.Use.Purpose = secrets.PurposeSecretSocket
	out.Use.Sources = nil
	out.Use.RegistrySources = nil
	if n.Socket != nil {
		out.Generation = n.Socket.Generation
		out.Sources = slices.Clone(n.Socket.Sources)
	}
	return out
}
