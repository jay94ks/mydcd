// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Image reference check (UI-3F image picker) in sfcd's real contract
// (REQ-31 `image-resolve`, docs/reference/image-resolution.md): sfcd
// normalizes the ref, picks the source the tenant would pull from (the
// built-in registry, an external source or an anonymous trusted host),
// checks the tenant's image trust and resolves the immutable digest. It is
// a preview: sfcd checks trust again at every pull. The web only shapes
// the answer.

type imageResolveView struct {
	Input        string              `json:"input"`
	Ref          string              `json:"ref"`
	Registry     string              `json:"registry,omitempty"` // authority (host[:port])
	RegistryKind string              `json:"registryKind"`       // builtin / external / unknown (anonymous)
	Source       string              `json:"source,omitempty"`   // the built-in or external source name
	Digest       string              `json:"digest,omitempty"`
	Pinned       string              `json:"pinned,omitempty"`
	MediaType    string              `json:"mediaType,omitempty"`
	Platforms    []imagePlatformView `json:"platforms"`
	Trusted      bool                `json:"trusted"`
	Rules        []resolveRuleView   `json:"rules"`
	Reason       string              `json:"reason,omitempty"`
	Code         string              `json:"code,omitempty"` // "" = resolved; else sfcd's code in lower case
}

type imagePlatformView struct {
	Platform string `json:"platform,omitempty"`
	Digest   string `json:"digest"`
}

type resolveRuleView struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
}

var resolveKinds = map[string]string{"managed": "builtin", "external": "external", "unknown": "unknown"}

// POST /t/{t}/images/resolve {ref} → imageResolveView. A ref sfcd cannot
// parse (INVALID_IMAGE) is 422 invalid-ref.
func (s *Server) handleImageResolve(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Ref string `json:"ref"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, ref := r.PathValue("t"), strings.TrimSpace(req.Ref)
	q := control.ImageResolveQuery{Ref: ref}
	if !q.Valid() {
		writeError(w, http.StatusUnprocessableEntity, "invalid-ref", "ref: 1 to 1024 bytes")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (imageResolveView, error) {
		res, err := c.ResolveImage(ctx, tenant, q)
		if err != nil {
			return imageResolveView{}, err
		}
		if res.Code == "INVALID_IMAGE" {
			return imageResolveView{}, &httpErr{http.StatusUnprocessableEntity, "invalid-ref", "not an image reference: " + ref}
		}
		return viewImageResolve(ref, res), nil
	})
}

func viewImageResolve(input string, res control.ImageResolveResult) imageResolveView {
	v := imageResolveView{Input: input, Ref: res.Normalized, RegistryKind: resolveKinds[res.Kind], Source: res.Source,
		Platforms: []imagePlatformView{}, Trusted: res.Trust.Trusted, Rules: []resolveRuleView{}}
	if v.RegistryKind == "" {
		v.RegistryKind = "unknown"
	}
	if res.Code != "OK" {
		v.Code = lowerCode(res.Code)
	}
	for _, t := range res.Trust.Rules {
		v.Rules = append(v.Rules, resolveRuleView{t.Registry, t.Repository})
	}
	// the authority of the normalized ref (host[:port]/repository:tag)
	if host, _, ok := strings.Cut(res.Normalized, "/"); ok {
		v.Registry = host
	}
	if img := res.Image; img != nil {
		v.Registry, v.Digest, v.Pinned, v.MediaType = img.Registry, img.Digest, img.Pinned, img.MediaType
		for _, p := range img.Platforms {
			pv := imagePlatformView{Digest: p.Digest}
			if pl := p.Platform; pl != nil {
				pv.Platform = pl.OS + "/" + pl.Architecture
				if pl.Variant != "" {
					pv.Platform += "/" + pl.Variant
				}
			}
			v.Platforms = append(v.Platforms, pv)
		}
	}
	if !v.Trusted {
		v.Reason = "no trust rule of this workspace matches " + res.Normalized
	}
	return v
}
