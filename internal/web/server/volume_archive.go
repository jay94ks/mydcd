// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/volumearchive"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Volume archives (devel/proposals/volume-archive-packages.md): "보관" packs
// a taken-down app's data store into a sealed file on its server and empties
// it; "되살리기" unpacks it in place. Nothing archives on its own (Jay
// 2026-11-28 09:37 KST). The daemon builds the payloads from the sfcd rows;
// sfcd decides (app down, clean exit, no consumer, both recipient keys).

// archiveView is one archive row as the screens show it.
type archiveView struct {
	ID          string `json:"id"`
	Node        string `json:"node"`
	Store       string `json:"store"`
	Phase       string `json:"phase"` // Packing Clearing Archived Restoring Restored Cancelling Cancelled Failed Discarding Discarded
	Compression string `json:"compression"`
	MaxBytes    uint64 `json:"maxBytes"`
	TarBytes    uint64 `json:"tarBytes,omitempty"`  // the files, packed size before compression
	DataBytes   uint64 `json:"dataBytes,omitempty"` // the package on disk
	Failure     string `json:"failure,omitempty"`
	Revision    uint64 `json:"revision"`
}

func archiveRow(j control.VolumeArchiveView) archiveView {
	return archiveView{ID: j.ID, Node: j.Node, Store: j.Root, Phase: j.Phase, Compression: string(j.Compression), MaxBytes: j.MaxBytes,
		TarBytes: j.TarBytes, DataBytes: j.DataBytes, Failure: j.Failure, Revision: j.Revision}
}

// volumeArchives reads the volume's archive rows (sfcd keeps the latest
// finished one and the one that holds the volume).
func volumeArchives(ctx context.Context, c sfc.Conn, v volumeView) ([]control.VolumeArchiveView, control.VolumeArchiveKeys, error) {
	var out []control.VolumeArchiveView
	var keys control.VolumeArchiveKeys
	after := ""
	for {
		p, err := c.VolumeArchives(ctx, v.Tenant, after)
		if err != nil {
			return nil, keys, err
		}
		keys = p.Keys
		for _, j := range p.Items {
			if j.Scope == v.Scope {
				out = append(out, j)
			}
		}
		if p.Next == "" {
			return out, keys, nil
		}
		after = p.Next
	}
}

// findArchive picks archive id of the volume; an empty id picks the one
// that holds the volume now.
func findArchive(ctx context.Context, c sfc.Conn, v volumeView, id string) (control.VolumeArchiveView, error) {
	if id == "" {
		id = v.ArchiveID
	}
	js, _, err := volumeArchives(ctx, c, v)
	if err != nil {
		return control.VolumeArchiveView{}, err
	}
	for _, j := range js {
		if j.ID == id && id != "" {
			return j, nil
		}
	}
	return control.VolumeArchiveView{}, &httpErr{http.StatusNotFound, "not-found", "no such archive"}
}

// POST /t/{t}/volumes/{name}/archive {opId, app?, id?, store?, compress?,
// maxBytes?, maxEntries?} → archive-volume. id defaults to "a-" + opId,
// store to the server's archive default (else its default storage root),
// compress to true (zstd), maxBytes to the capacity (else twice the used
// bytes, at least 1 GiB). App data stores only (409 no-app); 409
// archive-keys when the administrator's key is not set.
func (s *Server) handleVolumeArchive(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID       string `json:"opId"`
		App        string `json:"app,omitempty"`
		ID         string `json:"id,omitempty"`
		Store      string `json:"store,omitempty"`
		Compress   *bool  `json:"compress,omitempty"`
		MaxBytes   uint64 `json:"maxBytes,omitempty"`
		MaxEntries uint32 `json:"maxEntries,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.volumeStep(w, r, ws, req.OpID, req.App, req, func(ctx context.Context, c sfc.Conn, v volumeView) (string, any, uint64, error) {
		if v.App == "" || v.Kind == "fixed" {
			return "", nil, 0, &httpErr{http.StatusConflict, "no-app", "only data stores that belong to an app are archived"}
		}
		id := req.ID
		if id == "" {
			id = "a-" + req.OpID
		}
		if !storageIDRE.MatchString(id) || !volumearchive.ValidID(id) || len(id) > 61 {
			return "", nil, 0, invalid("id: lowercase letters, digits and -, starting with a letter (at most 61)")
		}
		if req.Store != "" && !storageIDRE.MatchString(req.Store) {
			return "", nil, 0, invalid("store: a storage root name")
		}
		maxBytes := req.MaxBytes
		if maxBytes == 0 {
			maxBytes = sizeHint(v)
		}
		if maxBytes < 1024 || maxBytes > 1<<40 {
			return "", nil, 0, invalid("maxBytes: 1024 .. 1 TiB")
		}
		entries := req.MaxEntries
		if entries == 0 {
			entries = 100000
		}
		if entries > 100000 {
			return "", nil, 0, invalid("maxEntries: 1 .. 100000")
		}
		compression := volumearchive.Zstd
		if req.Compress != nil && !*req.Compress {
			compression = volumearchive.None
		}
		_, keys, err := volumeArchives(ctx, c, v)
		if err != nil {
			return "", nil, 0, err
		}
		if keys.Cluster == ([32]byte{}) || keys.Admin == ([32]byte{}) {
			return "", nil, 0, &httpErr{http.StatusConflict, "archive-keys", "the cluster or administrator archive key is not set yet (sfcli volume archive admin-key)"}
		}
		q := control.VolumeArchiveBegin{Scope: v.Scope, ID: id, Root: req.Store, Compression: compression, MaxBytes: maxBytes, MaxEntries: entries}
		return sfc.ActionArchiveVolume, q, v.Revision, nil
	})
}

// POST /t/{t}/volumes/{name}/unarchive {opId, app?, id?} → unarchive-volume
// (id defaults to the archive that holds the volume).
// POST /t/{t}/volumes/{name}/archives/{id}/cancel {opId, app?} → cancel-volume-archive
// DELETE /t/{t}/volumes/{name}/archives/{id} {opId, app?} → discard-volume-archive
func (s *Server) handleArchiveSelection(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID string `json:"opId"`
			App  string `json:"app,omitempty"`
			ID   string `json:"id,omitempty"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		id := r.PathValue("id")
		if id == "" {
			id = req.ID
		} else if req.ID != "" && req.ID != id {
			writeError(w, http.StatusBadRequest, "invalid", "id: give it in the path or the body, not both")
			return
		}
		body := struct {
			Action string
			Req    any
		}{action, req}
		s.volumeStep(w, r, ws, req.OpID, req.App, body, func(ctx context.Context, c sfc.Conn, v volumeView) (string, any, uint64, error) {
			j, err := findArchive(ctx, c, v, id)
			if err != nil {
				return "", nil, 0, err
			}
			return action, control.VolumeArchiveSelection{Scope: j.Scope, ID: j.ID}, j.Revision, nil
		})
	}
}
