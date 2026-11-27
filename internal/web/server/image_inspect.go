// SPDX-License-Identifier: Apache-2.0

package server

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Layer view (UI-89) and tag add over the registry API with a pull (and for
// tags push) credential sfcd issues for the repository.

type layerView struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Bytes     int64  `json:"bytes"`
	CreatedBy string `json:"createdBy,omitempty"`
}

type historyView struct {
	Created    string `json:"created,omitempty"`
	CreatedBy  string `json:"createdBy,omitempty"`
	Comment    string `json:"comment,omitempty"`
	EmptyLayer bool   `json:"emptyLayer,omitempty"`
}

type platformView struct {
	Platform string `json:"platform"`
	Digest   string `json:"digest"`
}

type manifestView struct {
	Repository string          `json:"repository"`
	Ref        string          `json:"ref"`
	Digest     string          `json:"digest"`
	MediaType  string          `json:"mediaType"`
	Manifest   json.RawMessage `json:"manifest"`
	Config     json.RawMessage `json:"config,omitempty"`
	Platforms  []platformView  `json:"platforms,omitempty"` // an index
	History    []historyView   `json:"history"`
	Layers     []layerView     `json:"layers"`
}

// GET /t/{t}/registries/{id}/images/manifest?repository=&ref=&platform= →
// {repository, ref, digest, mediaType, manifest, config?, platforms?,
// history, layers}. ref is a tag or a digest. For a multi-platform index
// the answer lists its platforms; platform= (os/arch[/variant]) opens one.
func (s *Server) handleImageManifest(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	repo, ref, plat := q.Get("repository"), q.Get("ref"), q.Get("platform")
	if ref == "" || !tagRE.MatchString(ref) && !validDigest(ref) {
		writeError(w, http.StatusBadRequest, "bad-request", "ref: a tag or sha256 digest")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	v, err := s.imageManifest(ctx, ws, r.PathValue("t"), r.PathValue("id"), repo, ref, plat)
	if err != nil {
		s.writeOpOutcome(w, ws, nil, 0, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) imageManifest(ctx context.Context, ws *webSession, tenant, id, repo, ref, plat string) (manifestView, error) {
	c, err := s.registryClient(ctx, ws, tenant, id, repo, "pull")
	if err != nil {
		return manifestView{}, err
	}
	body, mt, dg, err := c.manifest(ctx, ref)
	if err != nil {
		return manifestView{}, err
	}
	v := manifestView{Repository: repo, Ref: ref, Digest: dg, MediaType: mt, Manifest: body, History: []historyView{}, Layers: []layerView{}}
	var m ociManifest
	if json.Unmarshal(body, &m) != nil {
		return manifestView{}, &httpErr{http.StatusBadGateway, "registry", "the manifest is not JSON"}
	}
	if m.MediaType == "" {
		m.MediaType = mt
	}
	if isIndexType(m.MediaType) || len(m.Manifests) > 0 {
		for _, d := range m.Manifests {
			if p := d.platform(); p != "" {
				v.Platforms = append(v.Platforms, platformView{p, d.Digest})
				if p == plat {
					child, err := s.imageManifest(ctx, ws, tenant, id, repo, d.Digest, "")
					if err != nil {
						return manifestView{}, err
					}
					child.Ref, child.Platforms = ref, v.Platforms
					return child, nil
				}
			}
		}
		if plat != "" {
			return manifestView{}, &httpErr{http.StatusNotFound, "not-found", "no such platform in the image"}
		}
		return v, nil
	}
	var cfg struct {
		History []struct {
			Created    string `json:"created"`
			CreatedBy  string `json:"created_by"`
			Comment    string `json:"comment"`
			EmptyLayer bool   `json:"empty_layer"`
		} `json:"history"`
	}
	raw, err := c.readBlobJSON(ctx, m.Config.Digest, &cfg)
	if err != nil {
		return manifestView{}, err
	}
	v.Config = raw
	// History rows without empty_layer line up with the layers in order.
	var made []string
	for _, h := range cfg.History {
		v.History = append(v.History, historyView{h.Created, h.CreatedBy, h.Comment, h.EmptyLayer})
		if !h.EmptyLayer {
			made = append(made, h.CreatedBy)
		}
	}
	for i, l := range m.Layers {
		lv := layerView{Digest: l.Digest, MediaType: l.MediaType, Bytes: l.Size}
		if i < len(made) && len(made) == len(m.Layers) {
			lv.CreatedBy = made[i]
		}
		v.Layers = append(v.Layers, lv)
	}
	return v, nil
}

type layerFile struct {
	Path     string `json:"path"`
	Bytes    int64  `json:"bytes"`
	Mode     string `json:"mode"`
	Type     string `json:"type"` // file / dir / symlink / hardlink / other
	Link     string `json:"link,omitempty"`
	Whiteout bool   `json:"whiteout,omitempty"` // deleted from lower layers
}

type layerFiles struct {
	Digest    string      `json:"digest"`
	Files     []layerFile `json:"files"`
	Truncated bool        `json:"truncated"`
}

const maxLayerFiles = 50000

// GET /t/{t}/registries/{id}/images/layer?repository=&digest= → {digest,
// files:[{path, bytes, mode, type, link?, whiteout?}], truncated}: the
// files one layer adds, changes or deletes (whiteout). The web keeps the
// list in its data folder by digest, and serves it again only after the
// registry confirms the caller's repository has that layer.
func (s *Server) handleLayerFiles(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	repo, dg := q.Get("repository"), q.Get("digest")
	if !validDigest(dg) {
		writeError(w, http.StatusBadRequest, "bad-request", "digest: sha256:<64 hex>")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	c, err := s.registryClient(ctx, ws, r.PathValue("t"), r.PathValue("id"), repo, "pull")
	if err == nil {
		var ok bool
		if ok, err = c.blobExists(ctx, dg); err == nil && !ok {
			err = &httpErr{http.StatusNotFound, "not-found", "no such layer in the repository"}
		}
	}
	if err != nil {
		s.writeOpOutcome(w, ws, nil, 0, err)
		return
	}
	cache := ""
	if s.opt.DataDir != "" {
		cache = filepath.Join(s.opt.DataDir, "layer-index", strings.TrimPrefix(dg, "sha256:")+".json")
		if raw, err := os.ReadFile(cache); err == nil {
			var lf layerFiles
			if json.Unmarshal(raw, &lf) == nil && lf.Digest == dg {
				writeJSON(w, http.StatusOK, lf)
				return
			}
		}
	}
	rc, _, err := c.blob(ctx, dg)
	if err != nil {
		s.writeOpOutcome(w, ws, nil, 0, err)
		return
	}
	defer rc.Close()
	lf, err := listLayer(rc, dg)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "layer", err.Error())
		return
	}
	if cache != "" {
		if raw, err := json.Marshal(lf); err == nil && os.MkdirAll(filepath.Dir(cache), 0o700) == nil {
			_ = os.WriteFile(cache, raw, 0o600)
		}
	}
	writeJSON(w, http.StatusOK, lf)
}

func listLayer(r io.Reader, dg string) (layerFiles, error) {
	br := bufio.NewReader(r)
	head, _ := br.Peek(4)
	var tr *tar.Reader
	switch {
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		zr, err := gzip.NewReader(br)
		if err != nil {
			return layerFiles{}, errors.New("the layer is not a readable gzip tar")
		}
		tr = tar.NewReader(zr)
	case len(head) >= 4 && head[0] == 0x28 && head[1] == 0xb5 && head[2] == 0x2f && head[3] == 0xfd:
		return layerFiles{}, errors.New("zstd layers cannot be listed yet")
	default:
		tr = tar.NewReader(br)
	}
	lf := layerFiles{Digest: dg, Files: []layerFile{}}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return layerFiles{}, errors.New("the layer is not a readable tar")
		}
		if len(lf.Files) >= maxLayerFiles {
			lf.Truncated = true
			break
		}
		p := cleanEntry(h.Name)
		f := layerFile{Path: "/" + p, Bytes: h.Size, Mode: os.FileMode(h.Mode).Perm().String()}
		dir, base := path.Split(p)
		if strings.HasPrefix(base, ".wh.") {
			f.Whiteout = true
			f.Path = "/" + dir + strings.TrimPrefix(base, ".wh.")
			if base == ".wh..wh..opq" {
				f.Path = "/" + strings.TrimSuffix(dir, "/")
			}
		}
		switch h.Typeflag {
		case tar.TypeReg:
			f.Type = "file"
		case tar.TypeDir:
			f.Type = "dir"
		case tar.TypeSymlink:
			f.Type, f.Link = "symlink", h.Linkname
		case tar.TypeLink:
			f.Type, f.Link = "hardlink", "/"+cleanEntry(h.Linkname)
		default:
			f.Type = "other"
		}
		lf.Files = append(lf.Files, f)
	}
	return lf, nil
}

// POST /t/{t}/registries/{id}/images/tag {repository, digest, tag,
// overwrite?} → {repository, tag, digest}: the same image under another tag
// (its manifest put again). A tag that points at another image answers 409
// tag-exists {current, usage} unless overwrite is true.
func (s *Server) handleTagImage(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Repository string `json:"repository"`
		Digest     string `json:"digest"`
		Tag        string `json:"tag"`
		Overwrite  bool   `json:"overwrite,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !validDigest(req.Digest) || !tagRE.MatchString(req.Tag) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "digest: sha256:<64 hex>; tag: letters, digits, _ . - (at most 128)")
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	ctx, cancel := s.callCtx(r)
	defer cancel()
	err := func() error {
		c, err := s.registryClient(ctx, ws, tenant, id, req.Repository, "pull", "push")
		if err != nil {
			return err
		}
		cur, err := c.headManifest(ctx, req.Tag)
		if err != nil {
			return err
		}
		if cur == req.Digest {
			return nil
		}
		if cur != "" && !req.Overwrite {
			return s.tagConflict(ctx, ws, c, tenant, req.Repository, req.Tag, cur)
		}
		body, mt, _, err := c.manifest(ctx, req.Digest)
		if err != nil {
			return err
		}
		return c.putManifest(ctx, req.Tag, mt, body)
	}()
	if err != nil {
		s.writeTagError(w, ws, err)
		return
	}
	s.images.drop(tenant, id)
	writeJSON(w, http.StatusOK, map[string]string{"repository": req.Repository, "tag": req.Tag, "digest": req.Digest})
}
