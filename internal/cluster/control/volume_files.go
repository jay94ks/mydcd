// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

type VolumeFileChange struct {
	Scope          volumes.Scope
	Path, After    string
	Size, MaxBytes int64
	Digest         [32]byte
	Overwrite      bool
}

func isVolumeFileAction(action string) bool {
	return action == "volume-file-put" || action == "volume-file-get" || action == "volume-file-list" || action == "volume-file-delete"
}
func (q VolumeFileChange) Valid(method string) bool {
	if !isVolumeFileAction(method) || q.Scope.Registry != "" || q.Scope.Generation == 0 || !access.ValidVolumeFilePath(q.Path, method == "volume-file-list") {
		return false
	}
	if method == "volume-file-put" {
		return q.Size >= 0 && q.MaxBytes > 0 && q.MaxBytes <= volumes.MaxFileBytes && q.Size <= q.MaxBytes && q.Digest != ([32]byte{}) && q.After == ""
	}
	if q.Overwrite || q.Size != 0 || q.Digest != ([32]byte{}) {
		return false
	}
	if method == "volume-file-get" {
		return q.MaxBytes > 0 && q.MaxBytes <= volumes.MaxFileBytes && q.After == ""
	}
	return q.MaxBytes == 0 && (method == "volume-file-list" && strings.HasSuffix(q.Path, "/") && (q.After == "" || access.ValidVolumeFilePath(q.After, false) && strings.HasPrefix(q.After, q.Path)) || method == "volume-file-delete" && q.After == "")
}

type VolumeFileJob struct {
	ID, Method, Phase, Code string
	Revision                uint64
	Request                 VolumeFileChange
	Native                  volumes.NativeReady
	Consumer                volumes.Consumer
	Origin                  UserOperation
	Result                  *volumes.FileResult `json:",omitempty"`
	Gone                    *volumes.Gone       `json:",omitempty"`
}

func VolumeFileID(op UserOperation) string {
	d := sha256.Sum256(append([]byte("sfc-volume-file-job-1\x00"), OperationBytes(op)...))
	return "file-" + hex.EncodeToString(d[:24])
}
func ownVolumeFile(j VolumeFileJob) VolumeFileJob {
	raw, _ := json.Marshal(j)
	var own VolumeFileJob
	_ = json.Unmarshal(raw, &own)
	return own
}
func (v Volumes) VolumeFile(id string) (VolumeFileJob, bool) {
	j, ok := v.files[id]
	return ownVolumeFile(j), ok
}
func (v Volumes) VolumeFiles() []VolumeFileJob {
	out := make([]VolumeFileJob, 0, len(v.files))
	for _, j := range v.files {
		out = append(out, ownVolumeFile(j))
	}
	slices.SortFunc(out, func(a, b VolumeFileJob) int { return strings.Compare(a.ID, b.ID) })
	return out
}
func validVolumeFileJob(j VolumeFileJob, cluster [32]byte) bool {
	if j.ID != VolumeFileID(j.Origin) || j.Method != j.Origin.Change.Action || !j.Request.Valid(j.Method) || j.Request.Scope.Cluster != cluster || j.Native.Verify() != nil || j.Native.Spec.Scope != j.Request.Scope || j.Origin.VerifyOriginal(cluster) != nil || j.Consumer.Owner != j.Native.Owner || j.Consumer.ID != j.ID || j.Consumer.Generation != 1 || j.Consumer.Writable != (j.Method == "volume-file-put" || j.Method == "volume-file-delete") {
		return false
	}
	var q VolumeFileChange
	if canonical(j.Origin.Change.Payload, &q) != nil || q != j.Request {
		return false
	}
	if j.Phase == "Reserved" {
		return j.Revision == 1 && j.Code == "" && j.Result == nil && j.Gone == nil
	}
	if j.Phase != "Completed" || j.Revision != 2 || j.Gone == nil || j.Gone.Scope != q.Scope || j.Gone.Consumer != j.Consumer || !j.Gone.Stopped || !j.Gone.MountsGone || !ed25519.Verify(j.Native.Owner.Key[:], volumes.GoneBytes(*j.Gone), j.Gone.Signature) {
		return false
	}
	switch j.Code {
	case "ok", "not-found", "conflict", "invalid", "limit", "cancelled", "unavailable":
	default:
		return false
	}
	if j.Code != "ok" {
		return j.Result == nil
	}
	if j.Method == "volume-file-put" {
		return j.Result != nil && j.Result.Path == q.Path && j.Result.Size == q.Size && j.Result.Digest == q.Digest
	}
	if j.Method == "volume-file-get" {
		return j.Result != nil && j.Result.Path == q.Path && j.Result.Size >= 0 && j.Result.Size <= q.MaxBytes
	}
	return j.Result == nil
}

func (p Policy) authorizeVolumeFile(c access.Catalog, op UserOperation) error {
	var q VolumeFileChange
	if canonical(op.Change.Payload, &q) != nil || !q.Valid(op.Change.Action) || q.Scope.Cluster != p.Cluster {
		return access.ErrInvalid
	}
	return c.AuthorizeVolumeFile(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Scope.Tenant, q.Scope.App, q.Scope.ID, q.Path, op.Change.Action, "")
}
func (p Policy) reduceVolumeFile(s state.State, c access.Catalog, v Volumes, op UserOperation) (map[string][]byte, state.Code) {
	var q VolumeFileChange
	if canonical(op.Change.Payload, &q) != nil || !q.Valid(op.Change.Action) {
		return nil, state.Invalid
	}
	id := VolumeFileID(op)
	if _, exists := v.files[id]; exists {
		return nil, state.ConditionFailed
	}
	if len(v.files) >= 256 {
		return nil, state.ConditionFailed
	}
	e, ok := v.entries[volumeKey(q.Scope)]
	if !ok || e.State.Scope() != q.Scope || e.State.Revision() != op.Change.Expected || e.State.Deleted() {
		return nil, state.ConditionFailed
	}
	owner, _ := e.State.Owner()
	key, err := p.workNodeOwner(s, owner.Node)
	if err != nil || key != owner.Key {
		return nil, state.Forbidden
	}
	if e.State.Fixed() {
		roots, err := p.NodeStorage(s)
		if err != nil {
			return nil, state.Invalid
		}
		if e.Native.Fixed == nil {
			return nil, state.Forbidden
		}
		ref := e.Native.Fixed.Root.Root
		root, exists := roots.Root(ref.Node, ref.ID)
		if !exists || root.Reference(p.Cluster) != ref || root.Draining || root.Closed != nil || root.Attestation == nil || !slices.Contains(root.Definition.Tenants, q.Scope.Tenant) {
			return nil, state.Forbidden
		}
	}
	var consumer volumes.Consumer
	e.State, consumer, err = e.State.AcquireFile(c, op.Session, p.Issuer(op.Session.Issuer), op.At, op.Change.Expected, id, 1, q.Path, op.Change.Action)
	if err != nil {
		return nil, state.ConditionFailed
	}
	e.Grants = append(e.Grants, volumeGrant{consumer, op.Session.User})
	v.entries[volumeKey(q.Scope)] = e
	v.files[id] = VolumeFileJob{ID: id, Method: op.Change.Action, Phase: "Reserved", Revision: 1, Request: q, Native: e.Native, Consumer: consumer, Origin: op}
	return p.volumeCheckpoint(s, v)
}

// VolumeFileWork is a fresh quorum read for one accepted original. It permits
// I/O only at the current exact native owner and current delegated user scope.
func (p Policy) VolumeFileWork(s state.State, caller [32]byte, session access.Session, id string, at int64) (VolumeFileJob, error) {
	p, err := p.Current(s)
	if err != nil {
		return VolumeFileJob{}, err
	}
	v, err := p.Volumes(s)
	if err != nil {
		return VolumeFileJob{}, err
	}
	j, ok := v.files[id]
	if !ok || (j.Phase != "Reserved" && j.Phase != "Completed") || !p.ownsResource(s, caller, j.Native.Owner.Key) || session.User != j.Origin.Session.User {
		return VolumeFileJob{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	q := j.Request
	if err != nil || c.AuthorizeVolumeFile(session, p.Cluster, p.Issuer(session.Issuer), at, q.Scope.Tenant, q.Scope.App, q.Scope.ID, q.Path, j.Method, j.Native.Owner.Node) != nil {
		return VolumeFileJob{}, access.ErrDenied
	}
	e, ok := v.entries[volumeKey(q.Scope)]
	if !ok || !sameVolumeNative(e.Native, j.Native) || j.Phase == "Reserved" && e.State.CheckActivation(j.Consumer) != nil {
		return VolumeFileJob{}, access.ErrDenied
	}
	key, err := p.workNodeOwner(s, j.Native.Owner.Node)
	if err != nil || key != caller {
		return VolumeFileJob{}, access.ErrDenied
	}
	return j, nil
}

type VolumeFileReport struct {
	Schema              uint8
	Operation, ID, Code string
	Epoch, RootRevision uint64
	At                  int64
	Result              *volumes.FileResult `json:",omitempty"`
	Gone                volumes.Gone
	Signature           []byte
}

func VolumeFileReportBytes(r VolumeFileReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-volume-file-report-1\x00"), raw...)
}
func volumeFileReportValue(raw []byte) bool {
	var h struct{ Operation string }
	return json.Unmarshal(raw, &h) == nil && h.Operation == "file"
}
func (p Policy) volumeFileReport(s state.State, cmd state.Command) (VolumeFileReport, error) {
	var r VolumeFileReport
	if cmd.Kind != state.ModuleReport || cmd.Key != VolumesKey || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Operation != "file" || r.At <= 0 || r.Epoch != cmd.Epoch || r.RootRevision != cmd.Expected || cmd.RequestID != state.ReportRequestID(cmd) {
		return r, access.ErrDenied
	}
	v, err := p.Volumes(s)
	if err != nil {
		return r, err
	}
	j, ok := v.files[r.ID]
	if !ok {
		return r, access.ErrDenied
	}
	key, err := p.nodeOwner(s, j.Native.Owner.Node)
	if err != nil || !p.ownsResource(s, key, j.Native.Owner.Key) || cmd.Actor != "node/"+hex.EncodeToString(key[:]) || !ed25519.Verify(key[:], VolumeFileReportBytes(r), r.Signature) {
		return r, access.ErrDenied
	}
	j.Phase, j.Revision, j.Code, j.Result, j.Gone = "Completed", 2, r.Code, r.Result, &r.Gone
	if !validVolumeFileJob(j, p.Cluster) {
		return r, access.ErrDenied
	}
	return r, nil
}
func (p Policy) ResolveVolumeFileReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	r, err := schema.Decode[VolumeFileReport](raw)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(caller[:]), Epoch: r.Epoch, Expected: r.RootRevision, Key: VolumesKey, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = p.volumeFileReport(s, cmd)
	return cmd, err
}
func (p Policy) reduceVolumeFileReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.volumeFileReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	j := v.files[r.ID]
	if j.Phase != "Reserved" {
		return nil, state.ConditionFailed
	}
	e := v.entries[volumeKey(j.Request.Scope)]
	e.State, err = e.State.Release(r.Gone)
	if err != nil {
		return nil, state.ConditionFailed
	}
	e.Grants = slices.DeleteFunc(e.Grants, func(g volumeGrant) bool { return g.Consumer == j.Consumer })
	v.entries[volumeKey(j.Request.Scope)] = e
	j.Phase, j.Revision, j.Code, j.Result, j.Gone = "Completed", 2, r.Code, r.Result, &r.Gone
	v.files[r.ID] = j
	return p.volumeCheckpoint(s, v)
}
