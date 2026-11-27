// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// route: a path from one tenant's network to another's. The source tenant
// proposes it and both tenants approve it before traffic flows.

func routeCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "route",
		Short: "Connect networks of two tenants (both must approve)",
		Sub: []*cli.Command{
			routeListCommand(g),
			routeEndpointsCommand(g),
			routeProposeCommand(g),
			routeSelectCommand(g, "approve"),
			routeSelectCommand(g, "withdraw"),
		},
	}
}

type routeView struct {
	ID        string        `json:"id"`
	From      string        `json:"from"`
	To        string        `json:"to"`
	Protocol  string        `json:"protocol"`
	Ports     string        `json:"ports"`
	Phase     string        `json:"phase"`
	Approvals []string      `json:"approvals"`
	Revision  uint64        `json:"revision"`
	Route     tenancy.Route `json:"-"`
}

// bindingText names a route side by its network name (the member ID when
// sfcd gives no name).
func bindingText(b tenancy.Binding, name string) string {
	if name == "" {
		name = b.Network
	}
	return b.Tenant + "/" + name + "@" + b.Node
}

func portsText(ports []tenancy.Ports) string {
	var parts []string
	for _, p := range ports {
		if p.First == p.Last {
			parts = append(parts, strconv.Itoa(int(p.First)))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", p.First, p.Last))
		}
	}
	return strings.Join(parts, ",")
}

func protocolText(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return strconv.Itoa(int(p))
}

func readRoutes(c *cli.Context, g *globals, s *session, tenant string) ([]routeView, uint64, error) {
	rows, networks, err := readResources(c, g, s, tenant)
	if err != nil {
		return nil, 0, err
	}
	out := []routeView{}
	for _, e := range rows {
		if e.Route == nil {
			continue
		}
		r := *e.Route
		var names control.RouteNames
		if e.RouteNames != nil {
			names = *e.RouteNames
		}
		v := routeView{ID: r.ID, From: bindingText(r.Source, names.Source), To: bindingText(r.Destination, names.Destination), Protocol: protocolText(r.Protocol), Ports: portsText(r.Ports), Phase: string(r.Phase), Approvals: []string{}, Revision: r.Revision, Route: r}
		for _, a := range r.Approvals {
			v.Approvals = append(v.Approvals, a.Tenant)
		}
		out = append(out, v)
	}
	return out, networks, nil
}

func routeListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List routes into and out of the tenant",
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			routes, _, err := readRoutes(c, g, s, tenant)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), routes, func() cli.Rows {
				r := cli.Rows{Header: []string{"name", "from", "to", "ports", "state", "approved by"}}
				for _, v := range routes {
					r.Add(v.ID, v.From, v.To, v.Protocol+" "+v.Ports, v.Phase, strings.Join(v.Approvals, ","))
				}
				return r
			})
		}),
	}
}

func routeEndpointsCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "endpoints",
		Args:  "TENANT",
		Short: "List the networks of a tenant that a route can reach",
		Run: guard(func(c *cli.Context, args []string) error {
			tenant, err := tenantArg(args, "TENANT")
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			endpoints, err := readEndpoints(c, g, s, tenant)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), endpoints, func() cli.Rows {
				r := cli.Rows{Header: []string{"endpoint", "pool"}}
				for _, e := range endpoints {
					r.Add(e.Tenant+"/"+e.Network+"@"+e.Node, e.Pool)
				}
				return r
			})
		}),
	}
}

func readEndpoints(c *cli.Context, g *globals, s *session, tenant string) ([]control.PublicRouteEndpoint, error) {
	out := []control.PublicRouteEndpoint{}
	err := publicReadAll(c, g, s, "route-endpoints", tenant, control.PublicReadQuery{}, func(r control.PublicReadRow) {
		if r.RouteEndpoint != nil {
			out = append(out, *r.RouteEndpoint)
		}
	})
	return out, err
}

// parseEndpoint reads TENANT/NETWORK@NODE[:POOL].
func parseEndpoint(text string) (control.RouteEndpoint, error) {
	var e control.RouteEndpoint
	rest, pool, _ := strings.Cut(text, ":")
	tn, node, ok := strings.Cut(rest, "@")
	tenant, network, ok2 := strings.Cut(tn, "/")
	if !ok || !ok2 || !cli.ValidID(tenant) || !cli.ValidID(network) || !cliprofile.ValidKeyName(node) || pool != "" && !cliprofile.ValidKeyName(pool) {
		return e, cli.Usagef("%q must look like TENANT/NETWORK@NODE", text)
	}
	return control.RouteEndpoint{Tenant: tenant, Network: network, Node: node, Pool: pool}, nil
}

// parsePorts reads 3306 or 8000-8100, separated by commas.
func parsePorts(text string) ([]tenancy.Ports, error) {
	var out []tenancy.Ports
	for _, part := range strings.Split(text, ",") {
		a, b, ranged := strings.Cut(part, "-")
		first, err := strconv.ParseUint(a, 10, 16)
		last := first
		if err == nil && ranged {
			last, err = strconv.ParseUint(b, 10, 16)
		}
		if err != nil || first == 0 || last < first {
			return nil, cli.Usagef("ports must look like 3306 or 8000-8100, separated by commas")
		}
		out = append(out, tenancy.Ports{First: uint16(first), Last: uint16(last)})
	}
	return out, nil
}

func routeProposeCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var from, to, tcp, udp string
	return &cli.Command{
		Name:  "propose",
		Args:  "NAME --from TENANT/NETWORK@NODE --to TENANT/NETWORK@NODE --tcp PORTS",
		Short: "Propose a route from your network to another tenant's",
		Long: `Propose a route named NAME. --from is your tenant's network member and
--to the other tenant's ('sfcli route endpoints TENANT' lists them). Add
':POOL' when a member has more than one address pool. The route opens once
both tenants have approved it with 'sfcli route approve'.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the networks are still at this `revision`")
			fs.StringVar(&from, "from", "", "source `TENANT/NETWORK@NODE`")
			fs.StringVar(&to, "to", "", "destination `TENANT/NETWORK@NODE`")
			fs.StringVar(&tcp, "tcp", "", "TCP `ports`, such as 3306 or 8000-8100")
			fs.StringVar(&udp, "udp", "", "UDP `ports`")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 1 || !cli.ValidID(args[0]) {
				return cli.Usagef("expected NAME --from ... --to ... --tcp PORTS")
			}
			source, err := parseEndpoint(from)
			if err != nil {
				return err
			}
			destination, err := parseEndpoint(to)
			if err != nil {
				return err
			}
			if (tcp == "") == (udp == "") {
				return cli.Usagef("give one of --tcp or --udp")
			}
			protocol, text := uint8(6), tcp
			if udp != "" {
				protocol, text = 17, udp
			}
			ports, err := parsePorts(text)
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			for _, e := range []*control.RouteEndpoint{&source, &destination} {
				if e.Pool != "" {
					continue
				}
				endpoints, err := readEndpoints(c, g, s, e.Tenant)
				if err != nil {
					return err
				}
				var pools []string
				for _, x := range endpoints {
					if x.Tenant == e.Tenant && x.Network == e.Network && x.Node == e.Node {
						pools = append(pools, x.Pool)
					}
				}
				if len(pools) != 1 {
					return fmt.Errorf("%s/%s@%s has %d address pools a route can use; name one with :POOL", e.Tenant, e.Network, e.Node, len(pools))
				}
				e.Pool = pools[0]
			}
			rev, err := revision.Resolve(func() (uint64, error) {
				_, networks, err := readResources(c, g, s, source.Tenant)
				return networks, err
			})
			if err != nil {
				return err
			}
			summary := fmt.Sprintf("route propose %s --from %s --to %s --%s %s", args[0], from, to, protocolText(protocol), text)
			q := control.RouteProposal{ID: args[0], Source: source, Destination: destination, Protocol: protocol, Ports: ports}
			if _, err = g.send(c, s, change{Summary: summary, ID: id.Get(), Action: "propose-route", Expected: rev, Payload: q}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "route %s proposed; both tenants approve it with 'sfcli route approve %s'\n", args[0], args[0])
			return nil
		}),
	}
}

// route approve|withdraw NAME: the current tenant's side of the route.
func routeSelectCommand(g *globals, verb string) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var sourceTenant string
	short := "Approve a route for your tenant's side"
	if verb == "withdraw" {
		short = "Withdraw your tenant's approval and close the route"
	}
	return &cli.Command{
		Name:  verb,
		Args:  "NAME",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the route is still at this `revision`")
			fs.StringVar(&sourceTenant, "source", "", "the route's source `tenant`, when two routes share NAME")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 1 || !cli.ValidID(args[0]) {
				return cli.Usagef("expected NAME")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			routes, _, err := readRoutes(c, g, s, tenant)
			if err != nil {
				return err
			}
			var found []routeView
			for _, r := range routes {
				if r.ID == args[0] && (sourceTenant == "" || r.Route.Source.Tenant == sourceTenant) {
					found = append(found, r)
				}
			}
			if len(found) == 0 {
				return fmt.Errorf("no route %s in %s", args[0], tenant)
			}
			if len(found) > 1 {
				return cli.Usagef("routes from several tenants are named %s; choose one with --source TENANT", args[0])
			}
			r := found[0]
			rev, err := revision.Resolve(func() (uint64, error) { return r.Revision, nil })
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Route %s: %s -> %s, %s %s\n", r.ID, r.From, r.To, r.Protocol, r.Ports)
			if verb == "withdraw" {
				if err = g.Prompter(c).Confirm("Withdraw the route?"); err != nil {
					return err
				}
			}
			summary := fmt.Sprintf("route %s %s --source %s", verb, r.ID, r.Route.Source.Tenant)
			q := control.RouteSelection{Tenant: tenant, SourceTenant: r.Route.Source.Tenant, ID: r.ID}
			if _, err = g.send(c, s, change{Summary: summary, ID: id.Get(), Action: verb + "-route", Expected: rev, Payload: q}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "route %s %s for %s\n", r.ID, map[string]string{"approve": "approved", "withdraw": "withdrawn"}[verb], tenant)
			return nil
		}),
	}
}
