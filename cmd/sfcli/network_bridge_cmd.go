// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// networkBridgeCommand is sfcli network bridge: virtual bridges that link two
// whole networks (devel/design/virtual-bridge.md 4).
func networkBridgeCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "bridge",
		Short: "Link two whole networks with a virtual bridge",
		Sub: []*cli.Command{
			networkBridgeListCommand(g),
			networkBridgeCreateCommand(g),
			networkBridgeSelectCommand(g, "approve", "Approve another tenant's bridge to your network"),
			networkBridgeSelectCommand(g, "close", "Close a bridge from either side"),
		},
	}
}

// bridgeView is how list prints a bridge. State is open, closing,
// waiting-me (this tenant has not approved) or waiting-peer.
type bridgeView struct {
	Owner     string                `json:"owner"`
	Name      string                `json:"name"`
	A         string                `json:"a"`
	B         string                `json:"b"`
	Direction string                `json:"direction"`
	Protocol  string                `json:"protocol"`
	Ports     string                `json:"ports"`
	State     string                `json:"state"`
	Revision  uint64                `json:"revision"`
	Bridge    tenancy.VirtualBridge `json:"-"`
}

func bridgeEndText(e tenancy.BridgeEnd) string { return e.Tenant + "/" + e.Network }

func viewBridge(tenant string, b tenancy.VirtualBridge) bridgeView {
	v := bridgeView{Owner: b.A.Tenant, Name: b.ID, A: bridgeEndText(b.A), B: bridgeEndText(b.B), Direction: string(b.Direction), Protocol: "all", Ports: portsText(b.Ports), Revision: b.Revision, Bridge: b}
	if b.Protocol != 0 {
		v.Protocol = protocolText(b.Protocol)
	}
	switch {
	case b.Phase == tenancy.BridgeOpen:
		v.State = "open"
	case b.Phase == tenancy.BridgeClosing:
		v.State = "closing"
	case tenant == b.B.Tenant:
		v.State = "waiting-me"
	default:
		v.State = "waiting-peer"
	}
	return v
}

func readBridges(c *cli.Context, g *globals, s *session, tenant string) ([]bridgeView, uint64, error) {
	rows, networks, err := readResources(c, g, s, tenant)
	if err != nil {
		return nil, 0, err
	}
	out := []bridgeView{}
	for _, e := range rows {
		if e.Bridge != nil {
			out = append(out, viewBridge(tenant, *e.Bridge))
		}
	}
	return out, networks, nil
}

func networkBridgeListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List the bridges with one of the tenant's networks as a side",
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
			bridges, _, err := readBridges(c, g, s, tenant)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), bridges, func() cli.Rows {
				r := cli.Rows{Header: []string{"owner", "name", "a", "b", "direction", "protocol", "ports", "state"}}
				for _, v := range bridges {
					r.Add(v.Owner, v.Name, v.A, v.B, v.Direction, v.Protocol, v.Ports, v.State)
				}
				return r
			})
		}),
	}
}

// bridgeDirection maps --direction: out starts from this network only
// (a-to-b), in from the other only (b-to-a).
func bridgeDirection(text string) (tenancy.BridgeDirection, error) {
	switch text {
	case "both":
		return tenancy.BridgeBoth, nil
	case "out":
		return tenancy.BridgeAToB, nil
	case "in":
		return tenancy.BridgeBToA, nil
	}
	return "", cli.Usagef("--direction is both, out or in")
}

func networkBridgeCreateCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var network, to, direction, protocol, ports string
	return &cli.Command{
		Name:  "create",
		Args:  "NAME --network NET --to [TENANT/]NET",
		Short: "Bridge one of your networks to another network",
		Long: `Create a virtual bridge named NAME between your network --network and
--to: every member server of one reaches every member server of the other.
Two networks of your tenant are linked at once. Another tenant's network
must take bridges (its bridge-inbound option), and its manager approves
with 'sfcli network bridge approve'. Two networks whose addresses overlap
are never linked; domain names are not shared.

--direction both (default), out (only your network starts connections) or
in (only the other network does). --protocol tcp|udp with --ports narrows
it; without them every protocol and port passes.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.StringVar(&network, "network", "", "your `network`")
			fs.StringVar(&to, "to", "", "the other `[TENANT/]NETWORK` (default tenant: yours)")
			fs.StringVar(&direction, "direction", "both", "`both`, out or in")
			fs.StringVar(&protocol, "protocol", "", "tcp or udp (default: every protocol)")
			fs.StringVar(&ports, "ports", "", "`PORTS` like 80 or 8000-8100, separated by commas (needs --protocol)")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 1 || !cli.ValidID(args[0]) {
				return cli.Usagef("expected NAME")
			}
			if !cli.ValidID(network) || to == "" {
				return cli.Usagef("--network and --to are required")
			}
			dir, err := bridgeDirection(direction)
			if err != nil {
				return err
			}
			q := control.BridgeProposal{ID: args[0], A: tenancy.BridgeEnd{Network: network}, Direction: dir}
			switch protocol {
			case "":
				if ports != "" {
					return cli.Usagef("--ports needs --protocol tcp or udp")
				}
			case "tcp", "udp":
				q.Protocol = map[string]uint8{"tcp": 6, "udp": 17}[protocol]
				if ports != "" {
					if q.Ports, err = parsePorts(ports); err != nil {
						return err
					}
				}
			default:
				return cli.Usagef("--protocol is tcp or udp")
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
			peerTenant, peerNetwork, cross := strings.Cut(to, "/")
			if !cross {
				peerTenant, peerNetwork = tenant, to
			}
			if !cli.ValidID(peerTenant) || !cli.ValidID(peerNetwork) {
				return cli.Usagef("--to must look like NETWORK or TENANT/NETWORK")
			}
			q.A.Tenant, q.B = tenant, tenancy.BridgeEnd{Tenant: peerTenant, Network: peerNetwork}
			_, revision, err := readResources(c, g, s, tenant)
			if err != nil {
				return err
			}
			impact := fmt.Sprintf("Bridge %s links %s and %s (%s).", q.ID, bridgeEndText(q.A), bridgeEndText(q.B), dir)
			summary := fmt.Sprintf("network bridge create %s --network %s --to %s", q.ID, network, bridgeEndText(q.B))
			if err = g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: summary, Action: "create-virtual-bridge", Expected: revision, Payload: q}); err != nil {
				return err
			}
			if peerTenant != tenant {
				fmt.Fprintf(c.Err, "The bridge opens once %s approves it (sfcli network bridge approve %s/%s).\n", peerTenant, tenant, q.ID)
			}
			return nil
		}),
	}
}

// networkBridgeSelectCommand is approve and close. OWNER is the creating
// tenant; close takes NAME alone for a bridge this tenant created.
func networkBridgeSelectCommand(g *globals, verb, short string) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	args := "OWNER/NAME"
	if verb == "close" {
		args = "[OWNER/]NAME"
	}
	return &cli.Command{
		Name:  verb,
		Args:  args,
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the bridge is still at this `revision`")
		},
		Run: guard(func(c *cli.Context, argv []string) error {
			if len(argv) != 1 {
				return cli.Usagef("expected %s", args)
			}
			owner, name, qualified := strings.Cut(argv[0], "/")
			if !qualified {
				owner, name = "", argv[0]
				if verb == "approve" {
					return cli.Usagef("expected OWNER/NAME: the tenant that created the bridge, and its name")
				}
			}
			if owner != "" && !cli.ValidID(owner) || !cli.ValidID(name) {
				return cli.Usagef("expected %s", args)
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
			if owner == "" {
				owner = tenant
			}
			bridges, _, err := readBridges(c, g, s, tenant)
			if err != nil {
				return err
			}
			var found *bridgeView
			for i := range bridges {
				if bridges[i].Owner == owner && bridges[i].Name == name {
					found = &bridges[i]
				}
			}
			if found == nil {
				return fmt.Errorf("no bridge %s/%s with a side in %s", owner, name, tenant)
			}
			rev, err := revision.Resolve(func() (uint64, error) { return found.Revision, nil })
			if err != nil {
				return err
			}
			impact := fmt.Sprintf("Bridge %s/%s: %s <-> %s, %s.", owner, name, found.A, found.B, found.State)
			if verb == "close" {
				impact += " Its servers stop reaching each other."
			}
			summary := fmt.Sprintf("network bridge %s %s/%s", verb, owner, name)
			q := control.BridgeSelection{Tenant: tenant, Owner: owner, ID: name}
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: summary, Action: verb + "-virtual-bridge", Expected: rev, Payload: q})
		}),
	}
}
