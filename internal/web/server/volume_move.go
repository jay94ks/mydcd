// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Data store move (UI-64), as `sfcli volume move-plan / move`. sfcd plans
// it (app-plan-stream with a move request) from the app document with the
// volume's new server; the daemon uploads the planned artifact under the
// move ID, sends begin-volume-move with sfcd's planned payload and
// Expected, and then gets the protected Group approvals of that original
// (the deploy job machinery, step Parts+2). The nodes copy, commit and
// switch; the source stays as a retained copy until delete-retained-volume.

type moveReq struct {
	OpID            string `json:"opId,omitempty"`
	App             string `json:"app,omitempty"`
	Node            string `json:"node,omitempty"` // the new server; sets volumes.{name}.x-sfc.node
	YAML            string `json:"yaml,omitempty"` // whole app document instead of the running one + node
	Digest          string `json:"digest,omitempty"`
	ID              string `json:"id,omitempty"`
	MaxBytes        uint64 `json:"maxBytes,omitempty"`
	MaxEntries      uint32 `json:"maxEntries,omitempty"`
	TransferSeconds uint32 `json:"transferSeconds,omitempty"`
}

func (q *moveReq) digest(name string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("volume-move\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00", name, q.App, q.Node, q.YAML, q.Digest, q.ID, q.MaxBytes, q.MaxEntries, q.TransferSeconds)))
	return hex.EncodeToString(h[:])
}

// setVolumeNode returns doc with volumes.{name}.x-sfc.node = node, keeping
// the rest of the document (and its comments) as written.
func setVolumeNode(doc []byte, name, node string) ([]byte, error) {
	return setMappingPath(doc, []string{"volumes", name, "x-sfc"}, "node", node)
}

// setMappingPath sets key: value in the mapping at path of a YAML document
// (missing mappings are made), keeping the rest of the document.
func setMappingPath(doc []byte, path []string, key, value string) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil {
		return nil, err
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("the app document is not a mapping")
	}
	child := func(m *yaml.Node, key string) *yaml.Node {
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == key {
				v := m.Content[i+1]
				if v.Kind != yaml.MappingNode {
					*v = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
				}
				return v
			}
		}
		v := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
		return v
	}
	x := root.Content[0]
	for _, p := range path {
		x = child(x, p)
	}
	for i := 0; i+1 < len(x.Content); i += 2 {
		if x.Content[i].Value == key {
			x.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
			return encodeYAML(&root)
		}
	}
	x.Content = append(x.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
	return encodeYAML(&root)
}

func encodeYAML(n *yaml.Node) ([]byte, error) {
	var b bytes.Buffer
	e := yaml.NewEncoder(&b)
	e.SetIndent(2)
	if err := e.Encode(n); err != nil {
		return nil, err
	}
	if err := e.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

type movePlanned struct {
	vol  volumeView
	app  sfc.AppView
	doc  []byte
	plan sfc.AppPlan
}

// planMove reads the volume and its app, builds the document and asks sfcd
// for the move plan.
func planMove(ctx context.Context, c sfc.Conn, tenant, name, id string, q *moveReq) (movePlanned, error) {
	var out movePlanned
	v, err := findVolume(ctx, c, tenant, name, q.App)
	if err != nil {
		return out, err
	}
	if v.App == "" {
		return out, &httpErr{http.StatusConflict, "no-app", "sfcd moves only data stores that belong to an app"}
	}
	if v.Phase == "Moving" {
		return out, &httpErr{http.StatusConflict, "moving", "this data store is already moving (" + v.MoveID + ")"}
	}
	apps, err := allApps(ctx, c, tenant)
	if err != nil {
		return out, err
	}
	i := slices.IndexFunc(apps, func(a sfc.AppView) bool { return a.App == v.App })
	if i < 0 || apps[i].Retiring {
		return out, &httpErr{http.StatusConflict, "app-not-running", "the data store's app is not running"}
	}
	out.vol, out.app = v, apps[i]
	if q.YAML != "" {
		if len(q.YAML) > 4<<20 {
			return out, invalid("yaml: at most 4 MiB")
		}
		out.doc = []byte(q.YAML)
	} else {
		if q.Node == "" {
			return out, invalid("node (the new server) or yaml is required")
		}
		src, err := c.AppSource(ctx, tenant, v.App, 0)
		if err != nil {
			return out, err
		}
		if out.doc, err = setVolumeNode(src.Document, v.Name, q.Node); err != nil {
			return out, &httpErr{http.StatusUnprocessableEntity, "invalid", "the running app document cannot be edited: " + err.Error()}
		}
	}
	sum := sha256.Sum256(out.doc)
	if q.Digest != "" && q.Digest != hex.EncodeToString(sum[:]) {
		return out, &httpErr{http.StatusConflict, "digest-mismatch", "the app document changed since the reviewed plan"}
	}
	maxBytes := q.MaxBytes
	if maxBytes == 0 {
		maxBytes = sizeHint(v)
	}
	if maxBytes < 1024 || maxBytes > 1<<40 {
		return out, invalid("maxBytes: 1024 .. 1 TiB")
	}
	entries := q.MaxEntries
	if entries == 0 {
		entries = 100000
	}
	if entries > 100000 {
		return out, invalid("maxEntries: 1 .. 100000")
	}
	seconds := q.TransferSeconds
	if seconds == 0 {
		seconds = 900
	}
	if seconds > 86400 {
		return out, invalid("transferSeconds: 1 .. 86400")
	}
	out.plan, err = c.AppPlan(ctx, sfc.AppPlanRequest{Tenant: tenant, Document: out.doc, Project: v.App, Deployment: out.app.Deployment,
		Move: &control.AppMovePlanRequest{Volume: v.Name, ID: id, MaxBytes: maxBytes, MaxEntries: entries, TransferSeconds: seconds}})
	if err != nil {
		return out, err
	}
	m := out.plan.Move
	if m == nil || m.Begin.ID != id || m.Begin.Scope.Tenant != tenant || m.Begin.Scope.App != v.App || m.Begin.Scope.ID != v.Name ||
		m.Begin.App == nil || m.Begin.App.Target == nil || m.Begin.App.Target.Upload != id || len(m.Artifact) == 0 || len(m.Artifact) > 4<<20 ||
		sha256.Sum256(m.Artifact) != m.Begin.App.Target.Plan {
		return out, &httpErr{http.StatusBadGateway, "plan-invalid", "the move plan does not match the request"}
	}
	return out, nil
}

func allApps(ctx context.Context, c sfc.Conn, tenant string) ([]sfc.AppView, error) {
	var out []sfc.AppView
	after := ""
	for {
		p, err := c.Apps(ctx, tenant, after)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Items...)
		if p.Next == "" {
			return out, nil
		}
		after = p.Next
	}
}

type movePlanView struct {
	Volume          string               `json:"volume"`
	App             string               `json:"app"`
	ID              string               `json:"id"`
	From            string               `json:"from"`
	To              string               `json:"to"`
	YAML            string               `json:"yaml"`
	Digest          string               `json:"digest"` // of yaml; send it back with the move
	CapacityBytes   uint64               `json:"capacityBytes"`
	MaxBytes        uint64               `json:"maxBytes"`
	MaxEntries      uint32               `json:"maxEntries"`
	ExpiresAt       string               `json:"expiresAt"`
	CD              bool                 `json:"cd"`
	Services        []sfc.PlannedService `json:"services"`
	TransferSeconds uint32               `json:"transferSeconds"` // as requested (sfcd's plan has only expiresAt)
}

// POST /t/{t}/volumes/{name}/move-plan {app?, node | yaml, id?, maxBytes?,
// maxEntries?, transferSeconds?} → the move sfcd would accept now.
func (s *Server) handleVolumeMovePlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req moveReq
	if !readJSON(w, r, &req) {
		return
	}
	id := req.ID
	if id == "" {
		id = "mv-plan"
	}
	if !storageIDRE.MatchString(id) || len(id) > 61 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "id: lowercase letters, digits and -, starting with a letter (at most 61)")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (movePlanView, error) {
		p, err := planMove(ctx, c, r.PathValue("t"), r.PathValue("name"), id, &req)
		if err != nil {
			return movePlanView{}, err
		}
		b := p.plan.Move.Begin
		sum := sha256.Sum256(p.doc)
		v := movePlanView{Volume: p.vol.Name, App: p.vol.App, ID: b.ID, From: p.vol.Node, To: b.Target.Node, YAML: string(p.doc), Digest: hex.EncodeToString(sum[:]),
			CapacityBytes: b.CapacityBytes, MaxBytes: b.MaxBytes, MaxEntries: b.MaxEntries, ExpiresAt: rfc3339(time.Unix(b.ExpiresAt, 0)), CD: b.App.CD != nil,
			Services: p.plan.Services, TransferSeconds: req.TransferSeconds}
		if v.Services == nil {
			v.Services = []sfc.PlannedService{}
		}
		if v.TransferSeconds == 0 {
			v.TransferSeconds = 900
		}
		return v, nil
	})
}

// POST /t/{t}/volumes/{name}/move {opId, app?, node | yaml, digest?, id?,
// maxBytes?, maxEntries?, transferSeconds?} → a move job (action
// volume-move): begin-app-upload → put-app-part × n → begin-volume-move →
// Group approvals (/apps/deploy/{opId}/approve). Sending the same opId
// again continues it, as a deploy job.
func (s *Server) handleVolumeMove(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req moveReq
	if !readJSON(w, r, &req) {
		return
	}
	tenant, name := r.PathValue("t"), r.PathValue("name")
	if !uuidRE.MatchString(req.OpID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4")
		return
	}
	id := req.ID
	if id == "" {
		id = "mv-" + req.OpID
	}
	if !storageIDRE.MatchString(id) || len(id) > 61 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "id: lowercase letters, digits and -, starting with a letter (at most 61)")
		return
	}
	dg := req.digest(name)
	parent, err := s.opt.Store.GetOp(ws.user.ID, req.OpID)
	switch {
	case err == nil:
		if parent.Digest != dg || parent.Deploy == nil || parent.Deploy.Move == nil || parent.Deploy.Tenant != tenant {
			writeError(w, http.StatusConflict, "op-conflict", "this opId was already used for a different change")
			return
		}
	case errors.Is(err, store.ErrNotFound):
		parent = nil
	default:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	err = ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		if parent == nil {
			p, err := planMove(ctx, c, tenant, name, id, &req)
			if err != nil {
				return err
			}
			b := p.plan.Move.Begin
			begin, err := json.Marshal(b)
			if err != nil {
				return err
			}
			art := []byte(p.plan.Move.Artifact)
			sum := sha256.Sum256(art)
			now := s.now()
			parent = &store.Op{ID: req.OpID, User: ws.user.ID, Username: ws.user.Username, Action: "volume-move", Tenant: tenant, Target: p.vol.Name,
				Digest: dg, State: store.OpRunning, SubmittedAt: now, UpdatedAt: now,
				Deploy: &store.DeployJob{Tenant: tenant, App: p.vol.App, Deployment: p.app.Deployment, UploadID: id,
					Document: art, Digest: hex.EncodeToString(sum[:]), Parts: (len(art) + sfc.AppPartBytes - 1) / sfc.AppPartBytes,
					Move: &store.MoveJob{Volume: p.vol.Name, ID: id, From: p.vol.Node, To: b.Target.Node, Begin: begin, Expected: p.plan.Move.Expected, CD: b.App.CD != nil}}}
			existing, err := s.opt.Store.CreateOp(parent)
			if err != nil {
				return err
			}
			if existing != nil {
				parent = existing
			}
		}
		return s.runDeploy(ctx, c, ws, parent, false)
	})
	if err != nil {
		var he *httpErr
		if errors.As(err, &he) {
			writeError(w, he.status, he.code, he.msg)
			return
		}
		s.writeBackendError(w, ws, err)
		return
	}
	writeJSON(w, opStatus(parent), map[string]any{"op": viewOp(parent)})
}

// POST /t/{t}/volumes/{name}/move/cancel {opId, app?, id?} →
// cancel-volume-move of the volume's current move (or id). sfcd refuses
// it once the owner is committed.
func (s *Server) handleVolumeMoveCancel(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		App  string `json:"app,omitempty"`
		ID   string `json:"id,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.volumeStep(w, r, ws, req.OpID, req.App, req, func(ctx context.Context, c sfc.Conn, v volumeView) (string, any, uint64, error) {
		id := req.ID
		if id == "" {
			id = v.MoveID
		}
		if v.Phase != "Moving" || id == "" || id != v.MoveID {
			return "", nil, 0, &httpErr{http.StatusConflict, "not-moving", "this data store has no such move in progress"}
		}
		return sfc.ActionCancelVolumeMove, control.VolumeMoveSelection{Scope: v.Scope, ID: id}, v.Revision, nil
	})
}

// DELETE /t/{t}/volumes/{name}/retained/{id} {opId, app?} →
// delete-retained-volume: removes the source copy a finished move kept.
func (s *Server) handleRetainedDelete(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		App  string `json:"app,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	s.volumeStep(w, r, ws, req.OpID, req.App, req, func(ctx context.Context, c sfc.Conn, v volumeView) (string, any, uint64, error) {
		if i := slices.IndexFunc(v.Retained, func(x volumeRetained) bool { return x.MoveID == id }); i >= 0 && v.Retained[i].State != "retained" {
			return "", nil, 0, &httpErr{http.StatusConflict, "not-retained", "this source copy is already being deleted or gone"}
		}
		return sfc.ActionDeleteRetained, control.VolumeMoveSelection{Scope: v.Scope, ID: id}, v.Revision, nil
	})
}
