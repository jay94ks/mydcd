// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Reading sfcd's `ingresses` (REQ-22, docs/reference/ingress-management.md)
// in full. A mappings page holds one mapping; its listeners, routes,
// backends, blocks and Runtime certificates/listeners/backends/blocks come
// 4 at a time by Offset, and so do the node's shared listener bindings.
// sfcd decides which rows the person sees; the web only joins the pages.

const (
	ingressMaxPages = 64  // mappings read per screen
	ingressMaxInner = 256 // offset pages per mapping (4 rows each)
)

// errIngressMoved: the selection changed between pages.
var errIngressMoved = errors.New("the external access state changed while reading; read again")

type ingressView struct {
	Root     uint64
	Mappings []control.IngressMapping
	Nodes    []control.IngressNodeSummary // in first-seen order, bindings joined
	nodeAt   map[string]int
}

func (v *ingressView) node(name string) *control.IngressNodeSummary {
	if i, ok := v.nodeAt[name]; ok {
		return &v.Nodes[i]
	}
	return nil
}

// ingressRead reads every mapping matching q (Node/Tenant/App/Key; Part and
// paging are set here) with its inner pages joined.
func ingressRead(ctx context.Context, c sfc.Conn, q control.IngressQuery) (*ingressView, error) {
	q.Part, q.Offset, q.After = "", 0, ""
	out := &ingressView{nodeAt: map[string]int{}}
	for range ingressMaxPages {
		p, err := c.QueryIngresses(ctx, q)
		if err != nil {
			return nil, err
		}
		out.Root = p.RootRevision
		newNodes := map[string]bool{}
		for _, n := range p.Nodes {
			if _, ok := out.nodeAt[n.Node]; !ok {
				out.nodeAt[n.Node] = len(out.Nodes)
				out.Nodes = append(out.Nodes, n)
				newNodes[n.Node] = true
			}
		}
		for _, m := range p.Mappings {
			full, err := ingressMappingRest(ctx, c, q, m, newNodes[m.Node], out)
			if err != nil {
				return nil, err
			}
			out.Mappings = append(out.Mappings, full)
		}
		if p.Next == "" {
			return out, nil
		}
		q.After = p.Next
	}
	return out, nil
}

// ingressMappingRest reads the offset pages after the first one of m and
// joins them into m. With gateways, the node's binding pages are joined too.
func ingressMappingRest(ctx context.Context, c sfc.Conn, q control.IngressQuery, m control.IngressMapping, gateways bool, v *ingressView) (control.IngressMapping, error) {
	more := func(p *control.IngressNodeSummary) bool {
		if !gateways || p == nil {
			return false
		}
		for _, g := range p.Gateways {
			if g.Next != 0 {
				return true
			}
		}
		return false
	}
	next := m.Next
	gw := more(v.node(m.Node))
	if gw {
		for _, g := range v.node(m.Node).Gateways {
			next = max(next, g.Next)
		}
	}
	if next == 0 {
		return m, nil
	}
	q.After, q.Key, q.Offset = "", m.Key, next
	for range ingressMaxInner {
		p, err := c.QueryIngresses(ctx, q)
		if err != nil {
			return m, err
		}
		if len(p.Mappings) != 1 || p.Mappings[0].Key != m.Key || p.Mappings[0].Offset != q.Offset {
			return m, errIngressMoved
		}
		x := p.Mappings[0]
		joinMapping(&m, x)
		var nextGW uint32
		if gw {
			for _, n := range p.Nodes {
				if n.Node == m.Node {
					joinGateways(v.node(m.Node), n)
					for _, g := range n.Gateways {
						nextGW = max(nextGW, g.Next)
					}
				}
			}
		}
		next := max(x.Next, nextGW)
		if next == 0 || next <= q.Offset {
			break
		}
		q.Offset = next
	}
	m.Offset, m.Next = 0, 0
	return m, nil
}

func joinMapping(m *control.IngressMapping, x control.IngressMapping) {
	m.Spec.Listeners = append(m.Spec.Listeners, x.Spec.Listeners...)
	m.Spec.Routes = append(m.Spec.Routes, x.Spec.Routes...)
	for _, svc := range x.Spec.Services {
		found := false
		for i := range m.Spec.Services {
			if m.Spec.Services[i].ID == svc.ID {
				m.Spec.Services[i].Backends = append(m.Spec.Services[i].Backends, svc.Backends...)
				found = true
			}
		}
		if !found {
			m.Spec.Services = append(m.Spec.Services, svc)
		}
	}
	m.Blocks = append(m.Blocks, x.Blocks...)
	if x.Runtime == nil {
		return
	}
	if m.Runtime == nil {
		r := *x.Runtime
		m.Runtime = &r
		return
	}
	r := m.Runtime
	r.Certificates = append(r.Certificates, x.Runtime.Certificates...)
	r.Listeners = append(r.Listeners, x.Runtime.Listeners...)
	r.Backends = append(r.Backends, x.Runtime.Backends...)
	r.Blocks = append(r.Blocks, x.Runtime.Blocks...)
}

func joinGateways(n *control.IngressNodeSummary, x control.IngressNodeSummary) {
	for _, g := range x.Gateways {
		for i := range n.Gateways {
			if n.Gateways[i].Gateway == g.Gateway {
				n.Gateways[i].Listeners = append(n.Gateways[i].Listeners, g.Listeners...)
				n.Gateways[i].Next = 0
			}
		}
	}
}

// ingressMetrics reads Part metrics (recent 60 s) or errors of one mapping
// with its dimension pages joined.
func ingressMetrics(ctx context.Context, c sfc.Conn, key, tenant, part string) (*ingress.Metrics, error) {
	q := control.IngressQuery{Key: key, Tenant: tenant, Part: part}
	var out *ingress.Metrics
	for range ingressMaxInner {
		p, err := c.QueryIngresses(ctx, q)
		if err != nil {
			return nil, err
		}
		if len(p.Mappings) != 1 || p.Mappings[0].Key != key {
			if out == nil {
				return nil, &httpErr{404, "not-found", "no such external access instance"}
			}
			return nil, errIngressMoved
		}
		x := p.Mappings[0]
		if x.Runtime == nil {
			return &ingress.Metrics{}, nil
		}
		mt := x.Runtime.Metrics
		if out == nil {
			out = &mt
		} else {
			out.Routes = append(out.Routes, mt.Routes...)
			out.Backends = append(out.Backends, mt.Backends...)
			out.Gateways = append(out.Gateways, mt.Gateways...)
			out.Conditions = append(out.Conditions, mt.Conditions...)
			out.Errors = append(out.Errors, mt.Errors...)
		}
		if x.Next == 0 || x.Next <= q.Offset {
			break
		}
		q.Offset = x.Next
	}
	return out, nil
}

// ingressPaged reads Part blocks or policies (numeric Offset in Next).
func ingressPaged(ctx context.Context, c sfc.Conn, q control.IngressQuery) (control.IngressPage, error) {
	var out control.IngressPage
	q.Offset, q.After = 0, ""
	for i := range ingressMaxInner {
		p, err := c.QueryIngresses(ctx, q)
		if err != nil {
			return out, err
		}
		if i == 0 {
			out = p
		} else {
			out.Blocks = append(out.Blocks, p.Blocks...)
			out.HostPolicies = append(out.HostPolicies, p.HostPolicies...)
			for _, n := range p.Nodes {
				if len(out.Nodes) == 0 {
					out.Nodes = append(out.Nodes, n)
				}
			}
		}
		if p.Next == "" {
			break
		}
		var off uint32
		if _, err := fmt.Sscan(p.Next, &off); err != nil || off <= q.Offset {
			break
		}
		q.Offset = off
	}
	out.Next = ""
	return out, nil
}
