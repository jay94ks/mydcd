// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"reflect"
	"time"
)

func (r Request) validIngressFields() bool {
	if (r.Ingress != nil) != (r.Method == "ingresses") {
		return false
	}
	if r.Ingress == nil {
		return true
	}
	want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Ingress: r.Ingress, Tenant: r.Tenant}
	return r.Ingress.Valid() && r.Tenant == r.Ingress.Tenant && reflect.DeepEqual(r, want)
}
func (s Service) ingressQuery(ctx context.Context, view cluster.View, session access.Session, q control.IngressQuery) Reply {
	if s.IngressObserver == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	page, err := s.IngressObserver(ctx, control.IngressRead{Session: session, Query: q, At: time.Now().Unix(), Index: view.State.Index()})
	if err != nil {
		code := "unavailable"
		if errors.Is(err, access.ErrDenied) || errors.Is(err, mydcp.ErrAdmission) {
			code = "denied"
		}
		return Reply{Schema: 1, Code: code}
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	current, err := s.Policy.IngressPage(latest.State, session, time.Now().Unix(), q)
	if err != nil || !page.SameSelection(current) {
		return Reply{Schema: 1, Code: "denied"}
	}
	return Reply{Schema: 1, Code: "ok", Ingress: &page}
}
func (c Client) Ingresses(ctx context.Context, peer mydcp.Peer, session access.Session, q control.IngressQuery) (control.IngressPage, error) {
	if !q.Valid() {
		return control.IngressPage{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "ingresses", Tenant: q.Tenant, Ingress: &q})
	if err != nil {
		return control.IngressPage{}, err
	}
	if reply.Ingress == nil || reply.Ingress.Schema != 1 || reply.Ingress.Index == 0 || len(reply.Ingress.Mappings) > 1 {
		return control.IngressPage{}, mydcp.ErrFrame
	}
	for _, row := range reply.Ingress.Mappings {
		if row.Key == "" || row.Generation == 0 || q.Node != "" && row.Node != q.Node || q.Tenant != "" && row.Tenant != q.Tenant || q.App != "" && row.App != q.App || q.Key != "" && row.Key != q.Key {
			return control.IngressPage{}, mydcp.ErrFrame
		}
	}
	return *reply.Ingress, nil
}

func (r Request) validCertificateFields() bool {
	method := r.Method == "certificates"
	if (r.Certificate != nil) != method {
		return false
	}
	if !method {
		return true
	}
	want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Certificate: r.Certificate}
	if !reflect.DeepEqual(r, want) {
		return false
	}
	if len(r.Certificate.After) > 512 {
		return false
	}
	return r.Certificate.Valid()
}
