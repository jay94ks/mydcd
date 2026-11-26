// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"slices"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Metadata only. Probe request/response bytes travel on the authenticated
// node stream, not the quorum reader or shared Raft state. The compact Run
// contains the Request once; its Definition is reconstructed from TaskProgram.
type CheckerProbeRequest struct {
	Schema            uint8
	Task              deployment.ObjectRef
	Binding           [32]byte
	Run               checker.Run
	Stop              *checker.ShutdownScope `json:",omitempty"`
	PolicyRevision    uint64
	Sequence          uint64
	Kind, Service     string
	Payload           [32]byte
	DeadlineUnixMilli int64
	At                int64 // Unix milliseconds, unlike older management At fields
}

// The nested signed Management envelope stays within its existing128KiB cap.
const MaxCheckerProbePermitBytes = 68 << 10

type CheckerProbePermit struct {
	Schema                                   uint8
	Binding, Program, Request, Call, Payload [32]byte
	Consumer, Provider                       [32]byte
	Target                                   contract.Target
	PolicyRevision, Index                    uint64
	DeadlineUnixMilli                        int64
}

func (p Policy) CheckerProbePermit(s state.State, caller [32]byte, q CheckerProbeRequest) (CheckerProbePermit, error) {
	deny := func() (CheckerProbePermit, error) { return CheckerProbePermit{}, access.ErrDenied }
	raw, err := json.Marshal(q)
	if err != nil || len(raw) > MaxCheckerProbePermitBytes || q.Schema != 1 || q.At < 0 || q.At > math.MaxInt64-30000 || q.Sequence == 0 || q.Sequence > checker.MaxProbeCalls || q.Payload == ([32]byte{}) || q.Run.PreparedAt > q.At || q.DeadlineUnixMilli <= q.At || q.DeadlineUnixMilli > q.Run.Request.DeadlineUnixMilli {
		return deny()
	}
	if q.Kind != "healthz" && q.Kind != "connect" && q.Kind != "file" && q.Kind != "exec" {
		return deny()
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) {
		return deny()
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return CheckerProbePermit{}, err
	}
	b, ok := apps.Binding(q.Task)
	if !ok || b.Digest() != q.Binding {
		return deny()
	}
	n := b.Needs()
	consumer := n.Use.NodeKey
	consumerCaller := p.currentResourceKey(s, consumer, false)
	if consumerCaller == ([32]byte{}) {
		return deny()
	}
	if q.Stop == nil {
		if _, err = p.appBindingPermitFromApps(s, consumerCaller, AppBindingRequest{Task: q.Task, Digest: q.Binding, At: q.At / 1000}, apps); err != nil {
			return deny()
		}
	} else {
		if _, err = p.CheckerShutdownPermit(s, consumerCaller, CheckerShutdownRequest{Schema: 1, Task: q.Task, Binding: q.Binding, Stop: *q.Stop, At: q.At / 1000}); err != nil {
			return deny()
		}
	}
	var goal deployment.GoalCommand
	var service deployment.ComposeService
	if canonical([]byte(s.Object(q.Task.Key).Value), &goal) != nil || goal.Owner != consumer || canonical(goal.Config, &service) != nil || service.CheckLifecycleNeeds(n) != nil || service.LifecycleProgram == nil {
		return deny()
	}
	program := service.LifecycleProgram
	book, err := p.Lifecycles(s)
	if err != nil || program.ValidateCatalog(book) != nil {
		return deny()
	}
	_, check, err := program.AppProbeDefinition(q.Run, q.Stop)
	if err != nil || q.Run.Request.App != n.Use.App || program.Service != n.Use.Service || program.Coordinator != n.Use.Service {
		return deny()
	}
	current, ok := book.Policy(n.Use.Tenant, 0)
	if !ok || !current.Enabled || current.Revision != q.PolicyRevision || !slices.Contains(current.Execution.Capabilities, q.Kind) || !slices.Contains(program.Policy.Execution.Capabilities, q.Kind) || q.DeadlineUnixMilli-q.At > current.Execution.TimeoutMS {
		return deny()
	}
	for _, fact := range program.Sources {
		if !current.AllowsSource(fact) {
			return deny()
		}
	}
	// Builtin inputs cannot request another category of effect. The receiver
	// also checks the complete typed payload with ValidateAppProbeCall.
	if check.Script == "" {
		want, wantService := "", ""
		if b := check.Builtin; b != nil {
			switch b.Kind {
			case "healthz":
				if b.HTTP != nil {
					want, wantService = "healthz", b.HTTP.Service
				}
			case "file":
				if b.File != nil {
					want, wantService = "file", b.File.Service
				}
			case "cmd":
				if b.Exec != nil {
					want, wantService = "exec", b.Exec.Service
				}
			}
		}
		if want != q.Kind || wantService != q.Service {
			return deny()
		}
	}
	var selected contract.Target
	for _, target := range q.Run.Request.Targets {
		if _, err := deployment.ResourceIDFromKey("task", n.Use.Tenant, n.Use.App, target.TaskKey); err != nil {
			return deny()
		}
		owner, err := identity.ParseKey(target.Owner)
		targetCaller := p.currentResourceKey(s, owner, false)
		if err != nil || targetCaller == ([32]byte{}) {
			return deny()
		}
		ref := deployment.ObjectRef{Key: target.TaskKey, Generation: target.Generation, Revision: target.Revision}
		targetBinding, ok := apps.Binding(ref)
		if !ok || targetBinding.Needs().Use.NodeKey != owner {
			return deny()
		}
		tu := targetBinding.Needs().Use
		if tu.Tenant != n.Use.Tenant || tu.App != n.Use.App || tu.Deployment != n.Use.Deployment || tu.User != n.Use.User || tu.Service != target.Service {
			return deny()
		}
		if q.Stop == nil {
			if _, err = p.appBindingPermitFromApps(s, targetCaller, AppBindingRequest{Task: ref, Digest: targetBinding.Digest(), At: q.At / 1000}, apps); err != nil {
				return deny()
			}
		} else {
			if _, err = p.checkerShutdownContext(s, targetCaller, CheckerShutdownRequest{Schema: 1, Task: ref, Binding: targetBinding.Digest(), Stop: *q.Stop, At: q.At / 1000}, false); err != nil {
				return deny()
			}
		}
		var targetGoal deployment.GoalCommand
		var declaration deployment.ComposeService
		if canonical([]byte(s.Object(ref.Key).Value), &targetGoal) != nil || targetGoal.Owner != owner || canonical(targetGoal.Config, &declaration) != nil || declaration.LifecycleProgram == nil || declaration.LifecycleProgram.Program != program.Program || declaration.LifecycleProgram.Service != target.Service {
			return deny()
		}
		instance, err := deployment.TaskInstanceForKey(n.Use.Tenant, n.Use.App, ref.Key, declaration)
		if err != nil || instance.Service != target.Service || instance.Node != tu.Node {
			return deny()
		}
		stamp, err := time.Parse(time.RFC3339Nano, target.StartedAt)
		if err != nil || stamp.IsZero() || stamp.UnixNano() <= 0 || !time.Unix(0, stamp.UnixNano()).Equal(stamp) {
			return deny()
		}
		if target.Service == program.Coordinator {
			if ref != q.Task || owner != consumer {
				return deny()
			}
			if claim, ok := apps.Claim(n.Use.Tenant, n.Use.App, ref); !ok || claim.Observation != nil && claim.Observation.Native != "" && claim.Observation.Native != target.NativeID {
				return deny()
			}
		} else {
			claim, ok := apps.Claim(n.Use.Tenant, n.Use.App, ref)
			o := claim.Observation
			if !ok || claim.Removed || o == nil || o.Released || o.Cluster != p.Cluster || o.Key != ref.Key || o.Generation != ref.Generation || o.Revision != ref.Revision || o.Owner != owner || o.Native != target.NativeID || o.OwnerBoot != target.OwnerBoot || o.StartedAt != stamp.UnixNano() || !o.Live(uint64(q.At/1000)) || !ed25519.Verify(owner[:], deployment.ObservationBytes(*o), o.Signature) {
				return deny()
			}
		}
		if target.Service == q.Service {
			selected = target
		}
	}
	provider, err := identity.ParseKey(selected.Owner)
	if err != nil || !p.ownsResource(s, caller, consumer) && !p.ownsResource(s, caller, provider) {
		return deny()
	}
	request := checker.ProbeBinding(q.Run.Request)
	call := checker.ProbeCall{Binding: request, Sequence: q.Sequence}.ID()
	return CheckerProbePermit{Schema: 1, Binding: q.Binding, Program: program.Program, Request: request, Call: call, Payload: q.Payload, Consumer: consumer, Provider: provider, Target: selected, PolicyRevision: current.Revision, Index: s.Index(), DeadlineUnixMilli: q.DeadlineUnixMilli}, nil
}

// Independent of a signed cache fact: a granted call still needs the exact
// payload and the provider's current native/credential checks before dispatch.
func (p CheckerProbePermit) Matches(q CheckerProbeRequest, call checker.ProbeCall) bool {
	service, err := call.TargetService(q.Run.Request)
	return err == nil && service == q.Service && p.Schema == 1 && p.Binding == q.Binding && p.Request == checker.ProbeBinding(q.Run.Request) && call.Binding == p.Request && p.Call == call.ID() && p.Payload == call.Digest() && p.Payload == q.Payload && call.Sequence == q.Sequence && call.Kind == q.Kind && call.DeadlineUnixMilli == q.DeadlineUnixMilli && p.DeadlineUnixMilli == q.DeadlineUnixMilli && p.Target.Service == q.Service && p.Target.Owner == hex.EncodeToString(p.Provider[:]) && slices.Contains(q.Run.Request.Targets, p.Target) && p.PolicyRevision == q.PolicyRevision && p.Index > 0 && p.Program != ([32]byte{}) && p.Provider != ([32]byte{}) && p.Consumer != ([32]byte{})
}

// HeaderDigest deliberately excludes caller/provider observation time. It
// preserves the original call through fresh permit reads and lost replies.
func (q CheckerProbeRequest) HeaderDigest() [32]byte {
	q.At = 0
	raw, _ := json.Marshal(q)
	return sha256.Sum256(append([]byte("mydc-checker-remote-call-1\x00"), raw...))
}
