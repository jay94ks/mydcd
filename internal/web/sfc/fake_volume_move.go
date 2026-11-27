// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Volume move (UI-64) in the fake, as `sfcli volume move-plan / move`: the
// plan stream with a move request returns a control.AppMovePlan whose
// artifact is the new document itself (the fake's "blueprint"); the client
// uploads it under the move ID and sends begin-volume-move (Expected: the
// volume revision). Node work is not modeled: the move stays Prepared until
// a test calls Fake.FinishVolumeMove, which needs the protected Group
// approvals of the begin-volume-move original (not for a CD app: its
// registrant approves with the CD selection) and then moves the volume,
// runs the uploaded document and keeps the source as a retained copy.
// cancel-volume-move finishes at once; delete-retained-volume marks the
// copy deleting until Fake.FinishRetainedDelete (the source server removed
// it), which marks it removed.

type fakeMove struct {
	begin control.VolumeMoveBegin
	op    UserOperation
	from  string
}

// fakeArtifact is the fake's move artifact: JSON (AppMovePlan.Artifact is
// raw JSON) carrying the planned document.
type fakeArtifact struct {
	FakeBlueprint int
	Document      string
}

func artifactDocument(art []byte) []byte {
	var a fakeArtifact
	if json.Unmarshal(art, &a) != nil || a.FakeBlueprint != 1 {
		return nil
	}
	return []byte(a.Document)
}

func moveKey(s volumes.Scope) string { return s.Tenant + "/" + s.App + "/" + s.ID }

// volumeNode reads volumes.<name>.x-sfc.node of an app document.
func volumeNode(doc []byte, name string) (node string, capacity uint64, ok bool) {
	var d struct {
		Volumes map[string]struct {
			XSfc struct {
				Node     string `yaml:"node"`
				Capacity uint64 `yaml:"capacity"`
			} `yaml:"x-sfc"`
		} `yaml:"volumes"`
	}
	if yaml.Unmarshal(doc, &d) != nil {
		return "", 0, false
	}
	v, ok := d.Volumes[name]
	return v.XSfc.Node, v.XSfc.Capacity, ok
}

func (w *world) movePlan(user string, req AppPlanRequest, at int64) (AppPlan, error) {
	const m = "app-plan-stream"
	q := req.Move
	if q.ID == "" || len(q.ID) > 61 || q.MaxBytes < 1024 || q.MaxBytes > 1<<40 || q.MaxEntries == 0 || q.MaxEntries > 100000 || q.TransferSeconds == 0 || q.TransferSeconds > 86400 || req.Diff {
		return AppPlan{}, fail(m, CodeInvalid, "move request")
	}
	i := slices.IndexFunc(w.volumes, func(v volumeRow) bool {
		return v.Tenant == req.Tenant && v.App == req.Project && v.Name == q.Volume
	})
	if i < 0 {
		return AppPlan{}, fail(m, CodeDenied, "")
	}
	v := w.volumes[i]
	a := w.apps[req.Tenant+"/"+req.Project]
	if a == nil || a.view.Retiring {
		return AppPlan{}, fail(m, CodeInvalid, "app is not running")
	}
	if v.Phase == "Moving" {
		return AppPlan{}, fail(m, CodeInvalid, "volume is moving")
	}
	if _, used := a.ops[q.ID]; used || w.uploads[req.Tenant+"/"+q.ID] != nil {
		return AppPlan{}, fail(m, CodeInvalid, "move ID in use")
	}
	d, err := parseApp(req.Document)
	if err != nil || d.Name != req.Project {
		return AppPlan{}, &Error{Code: CodeInvalid, Method: m, InputCode: "APP_DOCUMENT_INVALID"}
	}
	node, capacity, ok := volumeNode(req.Document, q.Volume)
	if node == "" {
		node = req.Node
	}
	if !ok {
		return AppPlan{}, &Error{Code: CodeInvalid, Method: m, InputCode: "VOLUME_NOT_DECLARED", Detail: q.Volume}
	}
	if node == v.Node || !w.knownNode(node) || !w.nodeAllowed(req.Tenant, node) {
		return AppPlan{}, fail(m, CodeDenied, "target node")
	}
	if capacity == 0 {
		capacity = v.CapacityBytes
	}
	if capacity < q.MaxBytes || capacity < v.CapacityBytes {
		return AppPlan{}, &Error{Code: CodeInvalid, Method: m, InputCode: "VOLUME_CAPACITY", Detail: "maxBytes above the capacity"}
	}
	art, err := json.Marshal(fakeArtifact{FakeBlueprint: 1, Document: string(req.Document)})
	if err != nil {
		return AppPlan{}, err
	}
	begin := control.VolumeMoveBegin{Scope: v.Scope, ID: q.ID, OwnerRevision: v.Revision,
		Target:        volumes.NativeSpec{Schema: 1, Scope: v.Scope, Node: node, NodeKey: fakeNodeKey(node), Materialization: "m-" + q.ID, UID: 999, GID: 999, Mode: 0o750, Retain: v.Retain},
		Compatibility: fakeDigest("compat", v.Key), MaxBytes: q.MaxBytes, MaxEntries: q.MaxEntries, CapacityBytes: capacity, ExpiresAt: at + int64(q.TransferSeconds),
		App: &control.VolumeMoveApp{Operation: a.view.Operation.ID, Plan: a.view.Operation.Plan, Revision: a.view.Revision,
			Target: &control.VolumeMoveTargetApp{Upload: q.ID, Operation: q.ID, Plan: sha256.Sum256(art)}}}
	if a.view.CD != nil {
		begin.App.CD = &control.AppCDMoveSource{Registration: fakeDigest("cd-registration", req.Tenant, req.Project), Principal: "cd-" + req.Project,
			Requester: fakeDigest("cd-requester", req.Tenant, req.Project), PolicyRevision: 1, Intent: fakeDigest("intent", string(art)), Input: fakeDigest("input", string(art))}
	}
	mp := control.AppMovePlan{Schema: 1, Expected: v.Revision, Epoch: 1, Begin: begin, Artifact: art}
	raw, err := json.Marshal(mp)
	if err != nil {
		return AppPlan{}, err
	}
	p, err := w.plan(req.Tenant, req.Document, false)
	if err != nil {
		return AppPlan{}, err
	}
	p.Digest, p.Length, p.Data, p.Move = sha256.Sum256(raw), len(raw), raw, &mp
	return p, nil
}

func (c *fakeConn) applyVolumeMove(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	switch ch.Action {
	case ActionBeginVolumeMove:
		var q control.VolumeMoveBegin
		if decodePayload(ch.Payload, &q) != nil || q.App == nil || q.App.Target == nil || q.Target.Materialization != "m-"+q.ID {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Scope.Tenant) {
			return errForbidden
		}
		i := w.volumeByScope(q.Scope)
		if i < 0 || w.volumes[i].Revision != ch.Expected || w.volumes[i].Phase == "Moving" || q.ExpiresAt <= c.f.now().Unix() {
			return errCAS
		}
		u := w.uploads[q.Scope.Tenant+"/"+q.App.Target.Upload]
		if u == nil || len(u.missing()) != 0 || u.view.App != q.Scope.App || sha256.Sum256(u.document()) != q.App.Target.Plan {
			return errors.New("upload incomplete")
		}
		if w.moves == nil {
			w.moves = map[string]*fakeMove{}
		}
		v := &w.volumes[i]
		w.moves[moveKey(q.Scope)] = &fakeMove{begin: q, op: op, from: v.Node}
		v.Phase, v.MoveID, v.TargetNode, v.MovePhase, v.Revision = "Moving", q.ID, q.Target.Node, string(volumes.Prepared), next
		return nil

	}
	return errors.New("action")
}

// FinishVolumeMove completes a Prepared move as the nodes would: the
// volume moves to the target, the uploaded document runs under the move
// ID and the source stays as a retained copy. It fails while a protected
// Group approval of the original is missing.
func (f *Fake) FinishVolumeMove(tenant, app, volume string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.w
	i := slices.IndexFunc(w.volumes, func(v volumeRow) bool { return v.Tenant == tenant && v.App == app && v.Name == volume })
	if i < 0 {
		return errors.New("no such volume")
	}
	mv := w.moves[moveKey(w.volumes[i].Scope)]
	if mv == nil {
		return errors.New("no move")
	}
	if mv.begin.App.CD == nil && len(w.missingApprovals(mv.op)) > 0 {
		return errors.New("group approval required")
	}
	u := w.uploads[tenant+"/"+mv.begin.App.Target.Upload]
	if u == nil {
		return errors.New("upload gone")
	}
	w.root++
	submitter := ""
	if usr := w.users[mv.op.Session.User]; usr != nil {
		submitter = usr.rec.Username
	}
	if _, err := w.deploy(tenant, app, artifactDocument(u.document()), submitter, mv.begin.ID, f.now().Unix()); err != nil {
		return err
	}
	delete(w.uploads, tenant+"/"+mv.begin.App.Target.Upload)
	delete(w.moves, moveKey(w.volumes[i].Scope))
	v := &w.volumes[i]
	v.Retained = append(slices.Clone(v.Retained), volumeRetainedRow{MoveID: mv.begin.ID, Node: mv.from, State: "retained"})
	v.Node, v.CapacityBytes, v.NativeBinding = mv.begin.Target.Node, mv.begin.CapacityBytes, fakeDigest("native", v.Key, mv.begin.ID)
	v.Phase, v.MoveID, v.TargetNode, v.MovePhase, v.Revision = "Ready", "", "", "", w.root
	return nil
}

// SetAppCD sets or clears (cd == nil) an app's CD registration, for tests.
func (f *Fake) SetAppCD(tenant, app string, cd *AppCD) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a := f.w.apps[tenant+"/"+app]; a != nil {
		a.view.CD = cd
	}
}
