// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"strconv"
	"strings"
)

// seedEvents reads every events page for tenant after cursor and gives the
// rows back in the seed shape the tests compare (fixtureOf). Next is the
// resume cursor.
func seedEvents(c Conn, tenant, after string) (Page[FixtureEvent], error) {
	out := Page[FixtureEvent]{}
	for {
		p, err := c.Events(ctx, EventQuery{Tenant: tenant, After: after, Limit: 100})
		if err != nil {
			return Page[FixtureEvent]{}, err
		}
		for _, it := range p.Items {
			out.Items = append(out.Items, fixtureOf(it))
		}
		out.Next, after = p.Cursor, p.Cursor
		if !p.More {
			return out, nil
		}
	}
}

// fixtureOf: a real events row back in the seed shape (target text from
// the Target fields).
func fixtureOf(it EventItem) FixtureEvent {
	t, d := it.Target, it.Detail
	e := FixtureEvent{Cursor: it.Cursor, Time: int64(it.At / 1000), Scope: it.Scope, Tenant: t.Tenant, App: t.App, Node: t.Node, Network: t.Network, PairID: t.PairID, Kind: it.Kind, Detail: d.Reason}
	switch {
	case t.PairID != "":
		e.Target = t.PairID
	case t.Service != "":
		e.Target = strings.Join([]string{t.Tenant, t.App, t.Service, t.Task}, "/")
	case t.FilesystemID != "":
		e.Target = t.Node + ":" + t.FilesystemID
	}
	if strings.HasPrefix(it.Kind, "cd-") {
		e.CD = &CDEvent{CandidateID: d.CandidateID, Commit: d.Commit, Actor: d.Actor, Code: d.Code, Reason: d.Reason}
		if d.FromVersion != 0 {
			e.CD.FromVersion = strconv.FormatUint(d.FromVersion, 10)
		}
		if d.ToVersion != 0 {
			e.CD.ToVersion = strconv.FormatUint(d.ToVersion, 10)
		}
	}
	if strings.HasPrefix(it.Kind, "ingress-") || t.Gateway != "" {
		e.Ingress = &IngressEvent{Gateway: t.Gateway, RouteID: t.RouteID, Host: t.Host, Prefix: t.Prefix, Value: float64(d.Value)}
	}
	if by := d.ClosedBy; by != nil {
		e.ShellClosedBy = &NodeShellUser{User: by.User, Username: by.Username}
	}
	return e
}
