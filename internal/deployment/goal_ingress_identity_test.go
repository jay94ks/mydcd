// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"crypto/ed25519"
	"encoding/json"
	"maps"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/engine"
)

func ingressIdentityGoals(t *testing.T, managed bool) (*fixture, map[string]state.Object, string, string) {
	t.Helper()
	var f *fixture
	var c Compose
	var ctx PlanningContext
	if managed {
		f, c, ctx = managedNetworkFixture(t)
	} else {
		f = makeFixture(t)
		c, ctx = smallCompose(t), contextFor(t, f)
	}
	declaration := &IngressDeclaration{Node: "node-a", Host: "app.test", Listeners: []ListenerDeclaration{{Address: "192.0.2.11:8080"}}, Runtime: IngressRuntime{MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100}}
	declaration.Backend.Service, declaration.Backend.Port, declaration.Backend.HealthPath = "web", 8080, "/readyz"
	c.MyDC.Ingress = declaration
	var blueprint Blueprint
	var err error
	if managed {
		blueprint, err = CompileApp(c, f.c, ctx)
	} else {
		blueprint, err = Compile(c, f.c, ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	objects := frozenManagedGoals(t, blueprint, ctx.Current)
	return f, objects, ResourceKey("ingress", blueprint.d.Tenant, blueprint.d.App, "http"), ResourceKey("task", blueprint.d.Tenant, blueprint.d.App, "web")
}

func readIngressIdentityGoal(t *testing.T, objects map[string]state.Object, key string) GoalCommand {
	t.Helper()
	var goal GoalCommand
	if json.Unmarshal([]byte(objects[key].Value), &goal) != nil {
		t.Fatal("original Goal input", key)
	}
	return goal
}
func putIngressIdentityGoal(t *testing.T, objects map[string]state.Object, key string, goal GoalCommand) {
	t.Helper()
	raw, err := json.Marshal(goal)
	if err != nil {
		t.Fatal(err)
	}
	o := objects[key]
	o.Value = string(raw)
	objects[key] = o
}

// All recipes/proofs are model inputs. Compile/Decode/ResolveIngress are the
// product cores; native restart, current membership and actual request serving
// remain in the original installed-resource fixture.
func TestIngressSameNodeCurrentAndRetainedGoalsKeepExactNativeAttachment(t *testing.T) {
	for _, managed := range []bool{false, true} {
		name := "legacy"
		if managed {
			name = "managed"
		}
		t.Run(name, func(t *testing.T) {
			f, original, ingressKey, taskKey := ingressIdentityGoals(t, managed)
			originalBytes := maps.Clone(original)
			before, err := ResolveIngress(f.cluster, ingressKey, original[ingressKey], original)
			if err != nil {
				t.Fatal("original same-node ingress", err)
			}
			next := private(78)
			for _, direction := range []string{"retained-listener-current-task", "current-listener-retained-task"} {
				t.Run(direction, func(t *testing.T) {
					objects := maps.Clone(original)
					ingressGoal := readIngressIdentityGoal(t, objects, ingressKey)
					taskGoal := readIngressIdentityGoal(t, objects, taskKey)
					currentKey := ingressKey
					if direction == "retained-listener-current-task" {
						currentKey = taskKey
					}
					current := readIngressIdentityGoal(t, objects, currentKey)
					current.Owner = public(next)
					current.ResourceKeys = replacementResourceKey(t, f.cluster, "node-a", f.na, next)
					object := objects[currentKey]
					object.Generation, object.Revision = object.Generation+1000, object.Revision+1000
					objects[currentKey] = object
					putIngressIdentityGoal(t, objects, currentKey, current)
					if currentKey == taskKey {
						taskGoal = current
						// The explicit replacement listener command pins the NEW
						// Task lifetime while retaining its original native owner.
						for i := range ingressGoal.Dependencies {
							if ingressGoal.Dependencies[i].Key == taskKey {
								ingressGoal.Dependencies[i] = ObjectRef{Key: taskKey, Generation: object.Generation, Revision: object.Revision}
							}
						}
						listener := objects[ingressKey]
						listener.Generation, listener.Revision = listener.Generation+1001, listener.Revision+1001
						objects[ingressKey] = listener
						putIngressIdentityGoal(t, objects, ingressKey, ingressGoal)
					} else {
						ingressGoal = current
					}
					spec, err := ResolveIngress(f.cluster, ingressKey, objects[ingressKey], objects)
					if err != nil || spec.Owner != engine.Owner(f.cluster, ingressGoal.Owner) || len(spec.Services) != 1 || len(spec.Services[0].Backends) != 1 || spec.Services[0].Backends[0].Task != taskKey || spec.Services[0].Backends[0].Network != before.Services[0].Backends[0].Network || spec.Services[0].Backends[0].Generation != objects[taskKey].Generation {
						t.Fatal("same physical-node recipes lost exact listener/backend/native identity", err)
					}
					if !sameNodeGoalOwner(f.cluster, ingressGoal, taskGoal) || !sameNodeGoalOwner(f.cluster, taskGoal, ingressGoal) {
						t.Fatal("same physical-node relation became directional")
					}
					for _, mutation := range []string{"absent-proof", "forged-proof", "wrong-cluster", "wrong-node", "unrelated-original"} {
						t.Run(mutation, func(t *testing.T) {
							changed := maps.Clone(objects)
							goal := current
							goal.ResourceKeys = lifecycle.OwnIdentityTransitions(current.ResourceKeys)
							switch mutation {
							case "absent-proof":
								goal.ResourceKeys = nil
							case "forged-proof":
								goal.ResourceKeys[0].Proof.NewSignature[0] ^= 1
							case "wrong-cluster", "wrong-node":
								proof := &goal.ResourceKeys[0].Proof
								if mutation == "wrong-cluster" {
									proof.Cluster[0]++
								} else {
									proof.Node = "node-b"
								}
								proof.OldSignature = ed25519.Sign(f.na, lifecycle.IdentityProofBytes(*proof))
								proof.NewSignature = ed25519.Sign(next, lifecycle.IdentityProofBytes(*proof))
							case "unrelated-original":
								goal.ResourceKeys = replacementResourceKey(t, f.cluster, "node-a", private(79), next)
							}
							putIngressIdentityGoal(t, changed, currentKey, goal)
							if _, err := ResolveIngress(f.cluster, ingressKey, changed[ingressKey], changed); err == nil {
								t.Fatal("unproven same-node owner relation accepted")
							}
						})
					}
					if managed {
						material, err := ResolveTaskNetwork(f.cluster, taskGoal, "app", objects)
						if err != nil || material.Reference == nil {
							t.Fatal("exact original native source", err)
						}
						changed := maps.Clone(objects)
						o := changed[material.Source.Key]
						o.Value += " "
						changed[material.Source.Key] = o
						if _, err := ResolveIngress(f.cluster, ingressKey, changed[ingressKey], changed); err == nil {
							t.Fatal("lineage bypassed the exact original network source hash")
						}
					}
					if !maps.Equal(originalBytes, original) {
						t.Fatal("same-node relation rewrote original Goal/native-reference bytes")
					}
				})
			}
		})
	}
}

func TestIngressSameNodeRejectsSignedForkAndDifferentRetainedPrefix(t *testing.T) {
	f, original, ingressKey, taskKey := ingressIdentityGoals(t, true)
	originalBytes := maps.Clone(original)
	objects := maps.Clone(original)
	left, right := private(80), private(81)
	ingressGoal := readIngressIdentityGoal(t, objects, ingressKey)
	taskGoal := readIngressIdentityGoal(t, objects, taskKey)
	ingressGoal.Owner = public(left)
	ingressGoal.ResourceKeys = replacementResourceKey(t, f.cluster, "node-a", f.na, left)
	taskGoal.Owner = public(right)
	taskGoal.ResourceKeys = replacementResourceKey(t, f.cluster, "node-a", f.na, right)
	putIngressIdentityGoal(t, objects, ingressKey, ingressGoal)
	putIngressIdentityGoal(t, objects, taskKey, taskGoal)
	if sameNodeGoalOwner(f.cluster, ingressGoal, taskGoal) {
		t.Fatal("two signed forks became one physical-node recipe")
	}
	if _, err := ResolveIngress(f.cluster, ingressKey, objects[ingressKey], objects); err == nil {
		t.Fatal("listener accepted another signed branch's Task")
	}
	// One continuation can name the retained listener key, but it must also
	// preserve that listener's already frozen proof/commit prefix exactly.
	continuation := replacementResourceKey(t, f.cluster, "node-a", left, right)[0]
	continuation.Proof.Operation = "ingress-continued"
	continuation.Index, continuation.Revision = 60, 60
	continuation.Proof.OldSignature = ed25519.Sign(left, lifecycle.IdentityProofBytes(continuation.Proof))
	continuation.Proof.NewSignature = ed25519.Sign(right, lifecycle.IdentityProofBytes(continuation.Proof))
	taskGoal.ResourceKeys = append(lifecycle.OwnIdentityTransitions(ingressGoal.ResourceKeys), continuation)
	if !sameNodeGoalOwner(f.cluster, ingressGoal, taskGoal) {
		t.Fatal("exact frozen prefix continuation was rejected")
	}
	putIngressIdentityGoal(t, objects, taskKey, taskGoal)
	if _, err := ResolveIngress(f.cluster, ingressKey, objects[ingressKey], objects); err != nil {
		t.Fatal("exact retained listener prefix lost backend continuation", err)
	}
	taskGoal.ResourceKeys[0].Index++
	if sameNodeGoalOwner(f.cluster, ingressGoal, taskGoal) {
		t.Fatal("different committed prefix was accepted as the retained identity")
	}
	putIngressIdentityGoal(t, objects, taskKey, taskGoal)
	if _, err := ResolveIngress(f.cluster, ingressKey, objects[ingressKey], objects); err == nil {
		t.Fatal("listener accepted a different retained prefix")
	}
	if !maps.Equal(originalBytes, original) {
		t.Fatal("original input changed")
	}
}
