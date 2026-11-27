// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Server image cache cleanup (node-image-cache.md, system admin). sfcd
// lists a server's Docker images with how many containers and shared
// references use each; only unused ones (both 0) can be removed, at most 8
// a prune. The web reads every list page and offers the first 8 unused
// images as the next prune; more unused images take another prune.

// imageCacheMaxPages bounds one walk of image-cache-plan (8 images a page).
const imageCacheMaxPages = 256

type imagePruneImage struct {
	Ref     string   `json:"ref"` // first alias, "" when the image has none
	Aliases []string `json:"aliases"`
	Digest  string   `json:"digest"` // the full image ID (sha256:…)
	Bytes   int64    `json:"bytes"`
}

// imagePruneView: GET /nodes/{node}/image-prune-plan.
type imagePruneView struct {
	Node   string            `json:"node"`
	Images []imagePruneImage `json:"images"` // the next prune's selection
	Bytes  int64             `json:"bytes"`  // sum of Docker's sizes, not space reclaimed
	Plan   string            `json:"plan"`   // token of the selection, sent back with the prune
	// Remaining: unused images beyond this selection; InUse: images some
	// container or shared reference still uses (kept).
	Remaining int `json:"remaining"`
	InUse     int `json:"inUse"`
	Total     int `json:"total"`
}

func imagePruneSelection(ctx context.Context, c sfc.Conn, node string) (imagePruneView, []string, error) {
	v := imagePruneView{Node: node, Images: []imagePruneImage{}}
	var ids []string
	after := ""
	for range imageCacheMaxPages {
		p, err := c.ImageCachePlan(ctx, sfc.ImageCacheQuery{Node: node, After: after})
		if err != nil {
			return v, nil, err
		}
		for _, img := range p.Images {
			v.Total++
			switch {
			case !img.Unused():
				v.InUse++
			case len(ids) == sfc.ImageCacheMaxImages:
				v.Remaining++
			default:
				ids = append(ids, img.ID)
				row := imagePruneImage{Aliases: img.Aliases, Digest: img.ID, Bytes: img.Bytes}
				if row.Aliases == nil {
					row.Aliases = []string{}
				}
				if len(row.Aliases) > 0 {
					row.Ref = row.Aliases[0]
				}
				v.Images = append(v.Images, row)
				v.Bytes += img.Bytes
			}
		}
		if p.Next == "" || p.Next <= after {
			break
		}
		after = p.Next
	}
	v.Plan = planToken(v.Images)
	return v, ids, nil
}

// GET /nodes/{node}/image-prune-plan → {node, images: [{ref, aliases,
// digest, bytes}], bytes, plan, remaining, inUse, total} (image-cache-plan
// pages). images are the next prune's selection, at most 8.
func (s *Server) handleNodeImagePrunePlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (imagePruneView, error) {
		v, _, err := imagePruneSelection(ctx, c, r.PathValue("node"))
		return v, err
	})
}

// imagePruneOperation: the prune-node-images Operation of a web opId.
func imagePruneOperation(opID string) string { return "op-" + opID }

// POST /nodes/{node}/image-prune {opId, plan} → prune-node-images
// (ImageCacheChange{Operation: "op-"+opId, Plan}, Expected 0). The web
// reads the selection again and asks sfcd for a plan of exactly those
// images; a selection that changed or is no longer all unused is 409
// plan-changed. Progress: GET /image-prunes/{operation}.
func (s *Server) handlePruneNodeImages(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		Plan string `json:"plan"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	node := r.PathValue("node")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if len(req.Plan) != 64 {
			return "", nil, 0, "", invalid("plan: the plan as shown (64 hex)")
		}
		changed := &httpErr{http.StatusConflict, "plan-changed", "the server's unused images changed; read the plan again"}
		cur, ids, err := imagePruneSelection(ctx, c, node)
		if err != nil {
			return "", nil, 0, "", err
		}
		if cur.Plan != req.Plan || len(ids) == 0 {
			return "", nil, 0, "", changed
		}
		p, err := c.ImageCachePlan(ctx, sfc.ImageCacheQuery{Node: node, Images: ids})
		if isSfcCode(err, sfc.CodeConflict) {
			return "", nil, 0, "", changed
		}
		if err != nil {
			return "", nil, 0, "", err
		}
		if !p.DeleteReady() {
			return "", nil, 0, "", changed
		}
		return sfc.ActionPruneNodeImages, sfc.ImageCacheChange{Operation: imagePruneOperation(req.OpID), Plan: p}, 0, "node/" + node, nil
	})
}

type imagePrunePart struct {
	Digest string `json:"digest"`
	State  string `json:"state"` // removed / already-absent / failed / skipped
	Code   string `json:"code,omitempty"`
	Error  string `json:"error,omitempty"`
	At     uint64 `json:"at"` // Unix seconds
}

type imagePruneStatusView struct {
	Operation string           `json:"operation"`
	User      string           `json:"user"`
	State     string           `json:"state"` // queued / running / done / failed
	Node      string           `json:"node"`
	At        uint64           `json:"at"` // Unix seconds
	Revision  uint64           `json:"revision"`
	Images    []string         `json:"images"` // the selection, in order
	Parts     []imagePrunePart `json:"parts"`  // settled images so far
}

// GET /image-prunes/{operation} → image-cache-status. Unknown is 404.
func (s *Server) handleImagePruneStatus(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (imagePruneStatusView, error) {
		st, err := c.ImageCacheStatus(ctx, r.PathValue("operation"))
		if isSfcCode(err, sfc.CodeMissing) || isSfcCode(err, sfc.CodeInvalid) {
			return imagePruneStatusView{}, &httpErr{http.StatusNotFound, "not-found", "no such image prune"}
		}
		if err != nil {
			return imagePruneStatusView{}, err
		}
		v := imagePruneStatusView{Operation: st.Operation, User: st.User, State: st.State, Node: st.Plan.Node, At: st.At, Revision: st.Revision,
			Images: append([]string{}, st.Plan.Selection...), Parts: []imagePrunePart{}}
		for _, p := range st.Parts {
			v.Parts = append(v.Parts, imagePrunePart{Digest: p.ID, State: p.State, Code: p.Code, Error: p.Error, At: p.At})
		}
		return v, nil
	})
}
