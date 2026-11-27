// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (s Service) containerObservation(ctx context.Context, view cluster.View, q Request, session access.Session) Reply {
	denied := Reply{Schema: 1, Code: "denied"}
	if s.ContainerObserver == nil || q.Container == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	target, err := s.Policy.ContainerTarget(view.State, session, time.Now().Unix(), q.Tenant, *q.Container)
	if err != nil {
		if errors.Is(err, containerops.ErrTarget) {
			return Reply{Schema: 1, Code: "unavailable"}
		}
		return denied
	}
	read := control.ContainerRead{Session: session, Target: target, Query: *q.Container}
	result, err := s.ContainerObserver(ctx, read)
	if err != nil || result.Validate(*q.Container, target) != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	current, err := s.Policy.ContainerTarget(latest.State, session, time.Now().Unix(), q.Tenant, *q.Container)
	if err != nil || !current.Matches(target) || result.Validate(*q.Container, current) != nil {
		return denied
	}
	if result.LogCode != "" {
		return Reply{Schema: 1, Code: "invalid", InputCode: result.LogCode}
	}
	if result.DetailCode != "" {
		return Reply{Schema: 1, Code: "invalid", InputCode: result.DetailCode}
	}
	return Reply{Schema: 1, Code: "ok", Tenant: q.Tenant, RootRevision: latest.State.Object(control.CatalogKey).Revision, Container: &result, ContainerViewIndex: latest.State.Index()}
}

// InspectContainer collects one immutable bounded snapshot; an interrupted or
// inconsistent assembly never returns partial detail as a complete result.
func (c Client) InspectContainer(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q containerops.Query) (Reply, error) {
	assembly, err := containerops.NewDetailAssembly(q)
	if err != nil {
		return Reply{}, err
	}
	defer assembly.Destroy()
	var reply Reply
	for {
		reply, err = c.ObserveContainer(ctx, peer, session, tenant, q)
		if err != nil {
			return Reply{}, err
		}
		if reply.Container == nil || assembly.Accept(q, *reply.Container) != nil {
			return Reply{}, sfcp.ErrFrame
		}
		var more bool
		q, more = assembly.Next()
		if !more {
			break
		}
	}
	result, err := assembly.Result()
	if err != nil {
		return Reply{}, sfcp.ErrFrame
	}
	reply.Container = &result
	return reply, nil
}

func (c Client) ObserveContainer(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q containerops.Query) (Reply, error) {
	if tenant == "" || q.Validate() != nil {
		return Reply{}, sfcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "container-observe", Tenant: tenant, Container: &q})
	if err != nil {
		return reply, err
	}
	if reply.Container == nil || reply.ContainerViewIndex == 0 || reply.Container.Target.Cluster != c.Cluster || reply.Container.Target.Tenant != tenant || !q.Selection.Matches(reply.Container.Target) || reply.Container.Validate(q, reply.Container.Target) != nil {
		return Reply{}, sfcp.ErrFrame
	}
	return reply, nil
}
