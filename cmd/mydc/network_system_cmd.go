// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"strings"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// networkSystemCommand is mydc network system: the system network
// mydc-system, which mydcd keeps itself (devel/design/node-apps.md 3.1).
func networkSystemCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "system",
		Short: "Show the system network for node apps, or change its address range",
		Sub: []*cli.Command{
			networkSystemShowCommand(g),
			networkSystemSetRangeCommand(g),
		},
	}
}

// systemNetworkView is how mydc network system show prints it.
type systemNetworkView struct {
	Range   string              `json:"range"`
	Users   []string            `json:"users"`
	Members []networkMemberView `json:"members"`
	// Revision is the networks revision a set-range is checked against.
	Revision uint64 `json:"revision"`
}

func readSystemNetwork(c *cli.Context, g *globals, s *session) (systemNetworkView, error) {
	rows, revision, err := readResources(c, g, s, "")
	if err != nil {
		return systemNetworkView{}, err
	}
	v := systemNetworkView{Users: []string{}, Members: []networkMemberView{}, Revision: revision}
	for _, e := range rows {
		switch {
		case e.System != nil:
			v.Range = e.System.RangeOrDefault().String()
			v.Users = append(v.Users, e.System.Users...)
		case e.Network != nil && e.Network.System:
			n := *e.Network
			m := networkMemberView{Node: n.Node, Subnet: poolText(n), Revision: n.Revision}
			if len(n.TunnelAddresses) != 0 {
				m.Tunnel = n.TunnelAddresses[0].String()
			}
			if n.Draining {
				m.Change = "draining"
			}
			v.Members = append(v.Members, m)
		}
	}
	if v.Range == "" {
		return v, errors.New("the server did not list the system network setting")
	}
	return v, nil
}

func networkSystemShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Short: "Show the system network: its range, the servers using it and its members",
		Long: `Show the system network mydc-system. mydcd makes it when a server
turns on a node app (node.yaml node_apps), joins every work server to it, and
removes it once no server uses it. Users are the servers that run node apps.
Reading it needs the system administrator.`,
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("show takes no arguments")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			v, err := readSystemNetwork(c, g, s)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows {
				users := "(none)"
				if len(v.Users) != 0 {
					users = strings.Join(v.Users, ",")
				}
				fmt.Fprintf(c.Out, "Range: %s\nUsed by: %s\n\n", v.Range, users)
				r := cli.Rows{Header: []string{"node", "subnet", "tunnel", "state"}}
				for _, m := range v.Members {
					state := "configured"
					if m.Change != "" {
						state = m.Change
					}
					r.Add(m.Node, m.Subnet, m.Tunnel, state)
				}
				return r
			})
		}),
	}
}

func networkSystemSetRangeCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	return &cli.Command{
		Name:  "set-range",
		Args:  "CIDR",
		Short: "Change the system network's address range (only while it has no members)",
		Long: `Change the system network's IPv4 address range, a /8 to /22 that no
other network uses. The first /24 holds the tunnel addresses and each server
gets the next free /24. It can change only while the network has no members:
turn node apps off on every server first. The default is ` + tenancy.DefaultSystemRange.String() + `.
Needs the cluster administrator.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected CIDR")
			}
			r, err := netip.ParsePrefix(args[0])
			if err != nil || !r.Addr().Is4() || r != r.Masked() || r.Bits() < 8 || r.Bits() > 22 {
				return cli.Usagef("%s is not an IPv4 network address from /8 to /22", args[0])
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			v, err := readSystemNetwork(c, g, s)
			if err != nil {
				return err
			}
			if len(v.Members) != 0 {
				return fmt.Errorf("the system network has %d members; turn node apps off on every server first", len(v.Members))
			}
			if v.Range == r.String() {
				return fmt.Errorf("the range is already %s", r)
			}
			impact := fmt.Sprintf("The system network range changes from %s to %s.", v.Range, r)
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "network system set-range " + r.String(), Action: "set-system-network-range", Expected: v.Revision, Payload: control.SystemNetworkRange{Range: r}})
		}),
	}
}
