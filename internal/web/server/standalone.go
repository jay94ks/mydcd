// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// Standalone containers (REQ-29, UI-3E·3F). mydcd owns the definition,
// the container, its lifetime and its limits; these endpoints only read
// mydcd's views, pass the definition text through and send the user's signed
// originals. The web keeps no standalone state of its own.

// standaloneView is the browser shape of one standalone container. Times
// are mydcd's Unix seconds.
type standaloneView struct {
	Name           string                  `json:"name"`
	Tenant         string                  `json:"tenant"`
	Lifetime       string                  `json:"lifetime"`
	Mode           string                  `json:"mode"`
	Image          string                  `json:"image"`
	Node           string                  `json:"node"`
	State          string                  `json:"state"`
	ExitCode       *int                    `json:"exitCode,omitempty"`
	Restarts       int                     `json:"restarts"`
	RestartPolicy  string                  `json:"restartPolicy,omitempty"`
	ExpiresAt      int64                   `json:"expiresAt,omitempty"`
	GraceSeconds   int                     `json:"graceSeconds,omitempty"`
	DisconnectedAt int64                   `json:"disconnectedAt,omitempty"`
	Connections    int                     `json:"connections"`
	Owner          string                  `json:"owner"`
	OwnerName      string                  `json:"ownerName,omitempty"`
	Revision       uint64                  `json:"revision"`
	Generation     uint64                  `json:"generation"`
	YAML           string                  `json:"yaml"`
	CreatedAt      int64                   `json:"createdAt"`
	EndedAt        int64                   `json:"endedAt,omitempty"`
	ObservedAt     int64                   `json:"observedAt"`
	ImportedFrom   *importedFromView       `json:"importedFrom,omitempty"`
	Selection      mydc.ContainerSelection `json:"-"`
}

// ownerNames maps user IDs to usernames for display. It asks mydcd for the
// tenant's members (managers can read them) and falls back to the ID.
func ownerNames(ctx context.Context, c mydc.Conn, ws *webSession, tenant string) map[string]string {
	names := map[string]string{ws.user.ID: ws.user.Username}
	after := ""
	for range 20 {
		p, err := c.TenantMembers(ctx, tenant, after)
		if err != nil {
			break
		}
		for _, m := range p.Items {
			names[m.User] = m.Username
		}
		if p.Next == "" {
			break
		}
		after = p.Next
	}
	return names
}

// importedFromView is the web's record of where a definition was copied from
// (UI-3E '가져온 설정'). It is absent when the container was made without a
// copy, by the CLI, or recreated outside the web after the copy.
type importedFromView struct {
	App        string   `json:"app"`
	Deployment string   `json:"deployment,omitempty"`
	Service    string   `json:"service"`
	Items      []string `json:"items,omitempty"`
	By         string   `json:"by"`
	At         int64    `json:"at"`
}

// importItems are the parts of an app service the form can copy.
var importItems = []string{"imageCmd", "netEnv", "volumes", "secrets", "ingress"}

func (s *Server) importedFrom(v mydc.StandaloneView) *importedFromView {
	o, err := s.opt.Store.StandaloneOrigin(v.Tenant, v.Name)
	// a container created after the copied up settled is another one
	if err != nil || o == nil || v.CreatedAt > o.SettledAt.Unix() {
		return nil
	}
	return &importedFromView{App: o.App, Deployment: o.Deployment, Service: o.Service, Items: o.Items, By: o.Username, At: o.At.Unix()}
}

// standaloneOriginSettled keeps the origin entries in step with their ops:
// an up's entry takes the op's final state, an applied remove forgets the
// container's origin and an applied pin with a new name moves it. The
// container is named by the signed original's payload, never by the
// browser's display target. An up's target is the server's own (the plan's
// name).
func (s *Server) standaloneOriginSettled(o *store.Op) {
	if !store.Settled(o.State) || o.Parent != "" {
		return // a standalone-up job's steps settle with the job
	}
	var err error
	switch o.Action {
	case mydc.ActionStandaloneUp:
		if o.Tenant != "" && o.Target != "" {
			err = s.opt.Store.SettleStandaloneOrigin(o.Tenant, o.Target, o.ID, o.State, time.Now())
		}
	case mydc.ActionStandaloneRemove, mydc.ActionStandalonePin:
		if o.State != store.OpApplied {
			return
		}
		op, derr := mydc.DecodeOperation(o.Signed)
		var p control.StandaloneChange
		if derr != nil || json.Unmarshal(op.Change.Payload, &p) != nil || p.Tenant == "" || p.Name == "" {
			s.log.Error("standalone origin: unreadable original", "op", o.ID)
			return
		}
		switch {
		case o.Action == mydc.ActionStandaloneRemove:
			err = s.opt.Store.DeleteStandaloneOrigins(p.Tenant, p.Name)
		case p.NewName != "" && p.NewName != p.Name:
			err = s.opt.Store.RenameStandaloneOrigins(p.Tenant, p.Name, p.NewName)
		}
	}
	if err != nil {
		s.log.Error("standalone origin", "err", err, "op", o.ID)
	}
}

func (s *Server) viewStandalone(v mydc.StandaloneView, names map[string]string) standaloneView {
	sv := viewStandalone(v, names)
	sv.ImportedFrom = s.importedFrom(v)
	return sv
}

func viewStandalone(v mydc.StandaloneView, names map[string]string) standaloneView {
	return standaloneView{Name: v.Name, Tenant: v.Tenant, Lifetime: v.Lifetime, Mode: v.Mode, Image: v.Image, Node: v.Node, State: v.State,
		ExitCode: v.ExitCode, Restarts: v.Restarts, RestartPolicy: v.RestartPolicy, ExpiresAt: v.ExpiresAt, GraceSeconds: v.GraceSeconds,
		DisconnectedAt: v.DisconnectedAt, Connections: v.Connections, Owner: v.Owner, OwnerName: names[v.Owner], Revision: v.Revision,
		Generation: v.Generation, YAML: string(v.Document), CreatedAt: v.CreatedAt, EndedAt: v.EndedAt, ObservedAt: v.ObservedAt, Selection: v.Selection}
}

// GET /t/{t}/standalone?all=1&after=: without all=1 the list holds the
// fixed containers and the caller's own temp ones; with all=1 everything
// mydcd lets the caller see (another user's temp only for a manager).
func (s *Server) handleStandaloneList(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, all := r.PathValue("t"), r.URL.Query().Get("all") == "1"
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (listPage, error) {
		p, err := c.Standalones(ctx, tenant, r.URL.Query().Get("after"))
		if err != nil {
			return listPage{}, err
		}
		names := ownerNames(ctx, c, ws, tenant)
		items := []standaloneView{}
		for _, v := range p.Items {
			if all || v.Lifetime == mydc.LifetimeFixed || v.Owner == ws.user.ID {
				items = append(items, s.viewStandalone(v, names))
			}
		}
		return s.page(items, p.Next, p.Revision), nil
	})
}

// GET /t/{t}/standalone/{name}
func (s *Server) handleStandaloneGet(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant := r.PathValue("t")
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (map[string]any, error) {
		v, err := c.Standalone(ctx, tenant, r.PathValue("name"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"item": s.viewStandalone(v, ownerNames(ctx, c, ws, tenant))}, nil
	})
}
