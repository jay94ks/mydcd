// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/firewall"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// nodeFirewallCommandTree is `sfcli node firewall`: a server's own inbound
// firewall chain, when its node.yaml lets sfcd control it.
func nodeFirewallCommandTree(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "firewall",
		Short: "Show or change a server's inbound firewall (system administrator)",
		Sub: []*cli.Command{
			nodeFirewallShowCommand(g),
			nodeFirewallRuleCommand(g, "allow"),
			nodeFirewallRuleCommand(g, "deny"),
			nodeFirewallUpdateCommand(g),
			nodeFirewallRemoveCommand(g),
			nodeFirewallPolicyCommand(g),
			nodeFirewallLogCommand(g),
		},
	}
}

func firewallCall(c *cli.Context, g *globals, s *session, op control.NodeFirewallOp) (control.NodeFirewallResult, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	r, err := s.Client.NodeFirewall(ctx, s.Target, s.Stored.Session, op)
	var reply *userauth.Error
	known := errors.As(err, &reply) && (reply.Code != "transport" || reply.Phase == sfcp.NotSent)
	if err != nil && op.Action == "change" && !known {
		return r, cli.ExitError{Code: exitUnknown, Err: fmt.Errorf("the result of firewall change %s is not known (%v); run the same command again with --id %s: it is applied at most once", op.Operation, err, op.Operation)}
	}
	return r, err
}

// firewallNow reads the server's firewall; it fails when sfcd may not
// control it.
func firewallNow(c *cli.Context, g *globals, s *session, node string) (*control.NodeFirewallView, error) {
	r, err := firewallCall(c, g, s, control.NodeFirewallOp{Node: node, Action: "show"})
	if err != nil {
		return nil, err
	}
	if r.Code != "" {
		return nil, fmt.Errorf("%s: %s", r.Code, r.Error)
	}
	if r.View == nil || !r.View.Managed {
		return nil, fmt.Errorf("sfcd does not control the firewall of %s; set firewall.managed: true in its node.yaml and restart sfcd there", node)
	}
	return r.View, nil
}

// firewallChange sends one delta at the revision just read and prints the
// outcome.
func firewallChange(c *cli.Context, g *globals, s *session, id cli.IDFlag, node string, revision uint64, d firewall.Delta) error {
	op := control.NodeFirewallOp{Operation: id.Get(), Node: node, Action: "change", Revision: revision, Delta: &d}
	r, err := firewallCall(c, g, s, op)
	if err != nil {
		return err
	}
	switch r.Code {
	case "":
	case "revision":
		now := uint64(0)
		if r.View != nil {
			now = r.View.Revision
		}
		return fmt.Errorf("the firewall of %s changed (now revision %d); look at it again with: sfcli node firewall show %s", node, now, node)
	default:
		return fmt.Errorf("%s: %s", r.Code, r.Error)
	}
	ch := r.Change
	return cli.Print(c.Out, g.output.Format(), r, func() cli.Rows {
		rows := cli.Rows{Header: []string{"field", "value"}}
		rows.Add("node", node)
		if ch != nil {
			rows.Add("revision", fmt.Sprintf("%d -> %d", ch.From, ch.To))
			if len(ch.Added) > 0 {
				rows.Add("added", strings.Join(ch.Added, ", "))
			}
		}
		if r.View != nil && !r.View.Applied {
			rows.Add("warning", "the chain does not hold these rules yet: "+r.View.ApplyError)
		}
		return rows
	})
}

func nodeFirewallShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "NODE",
		Short: "Show a server's firewall rules, locked rules and the server's other input rules (nft expressions)",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			node, err := nodeArg(args, "firewall show")
			if err != nil {
				return err
			}
			r, err := firewallCall(c, g, s, control.NodeFirewallOp{Node: node, Action: "show"})
			if err != nil {
				return err
			}
			if r.Code != "" {
				return fmt.Errorf("%s: %s", r.Code, r.Error)
			}
			v := r.View
			return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows {
				rows := cli.Rows{Header: []string{"kind", "id", "rule", "note"}}
				if v == nil || !v.Managed {
					rows.Add("-", "-", "not controlled", "node.yaml firewall.managed is off on "+node)
					return rows
				}
				policy := firewallPolicyText(v.Policy)
				if v.Policy == firewall.PolicyInherit {
					policy += ": now " + v.Effective
				}
				rows.Add("policy", "-", policy, fmt.Sprintf("revision %d, %d/%d rules", v.Revision, len(v.Rules), v.MaxRules))
				if !v.Applied {
					rows.Add("warning", "-", "chain does not hold the saved rules", v.ApplyError)
				}
				for _, l := range v.Locked {
					rule := "-"
					if l.Proto != "" {
						rule = fmt.Sprintf("%s/%d", l.Proto, l.Port)
					}
					if len(l.From) > 0 {
						rule += " from " + strings.Join(l.From, ",")
					}
					rows.Add("locked", l.Name, rule, l.Reason)
				}
				var cluster []firewall.Rule
				if v.Cluster != nil {
					cluster = v.Cluster.Rules
				}
				required, rest := []firewall.Rule{}, []firewall.Rule{}
				for _, r := range cluster {
					if r.Required {
						required = append(required, r)
					} else {
						rest = append(rest, r)
					}
				}
				clusterFirewallRows(&rows, required, "cluster ")
				shadowed := map[string]bool{}
				for _, id := range v.Shadowed {
					shadowed[id] = true
				}
				for _, action := range []string{"deny", "allow"} {
					for _, rule := range v.Rules {
						if rule.Action == action {
							note := rule.Comment
							if shadowed[rule.ID] {
								note = strings.TrimSpace("partly overridden by a required cluster rule " + note)
							}
							rows.Add(action, rule.ID, firewallRuleText(rule), note)
						}
					}
				}
				clusterFirewallRows(&rows, rest, "cluster ")
				if v.Cluster != nil {
					rows.Add("cluster", "-", "policy "+v.Cluster.Policy, fmt.Sprintf("cluster revision %d (sfcli firewall show)", v.Cluster.Revision))
				}
				for _, line := range v.Operator {
					rows.Add("server", "-", line, "nft expression, read only")
				}
				if v.OperatorTruncated {
					rows.Add("server", "-", "…", "more input rules not shown")
				}
				return rows
			})
		}),
	}
}

func firewallRuleText(r firewall.Rule) string {
	s := r.Proto
	if r.Ports != "" {
		s += "/" + r.Ports
	}
	if len(r.From) > 0 {
		s += " from " + strings.Join(r.From, ",")
	} else {
		s += " from anywhere"
	}
	return s
}

// parseFirewallProto reads tcp/443, udp/30000-30100, icmp or any.
func parseFirewallProto(s string) (proto, ports string, err error) {
	proto, ports, _ = strings.Cut(s, "/")
	switch proto {
	case "tcp", "udp":
		if ports == "" {
			return "", "", cli.Usagef("%s needs a port, such as %s/443", proto, proto)
		}
	case "icmp", "any":
		if ports != "" {
			return "", "", cli.Usagef("%s takes no port", proto)
		}
	default:
		return "", "", cli.Usagef("%q must be tcp/PORT, udp/PORT, a range such as tcp/30000-30100, icmp or any", s)
	}
	return proto, ports, nil
}

func nodeFirewallRuleCommand(g *globals, action string) *cli.Command {
	var id cli.IDFlag
	var from listFlag
	var comment string
	short := "Let traffic in"
	if action == "deny" {
		short = "Drop traffic (deny rules are checked before allow rules)"
	}
	return &cli.Command{
		Name:  action,
		Args:  "NODE tcp/PORT|udp/PORT|icmp|any [--from PREFIX]...",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&from, "from", "source `prefix` such as 203.0.113.0/24; repeat for more (default: anywhere)")
			fs.StringVar(&comment, "comment", "", "a short note")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 2 {
				return cli.Usagef("%s needs a node name and what to match, such as: sfcli node firewall %s vps1 tcp/443", action, action)
			}
			node, err := nodeArg(args[:1], "firewall "+action)
			if err != nil {
				return err
			}
			proto, ports, err := parseFirewallProto(args[1])
			if err != nil {
				return err
			}
			v, err := firewallNow(c, g, s, node)
			if err != nil {
				return err
			}
			return firewallChange(c, g, s, id, node, v.Revision, firewall.Delta{Add: []firewall.Rule{{Action: action, Proto: proto, Ports: ports, From: from, Comment: comment}}})
		}),
	}
}

func findFirewallRule(v *control.NodeFirewallView, id string) (firewall.Rule, bool) {
	for _, r := range v.Rules {
		if r.ID == id {
			return r, true
		}
	}
	return firewall.Rule{}, false
}

func nodeFirewallUpdateCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var from listFlag
	var action, match, comment string
	var anywhere bool
	return &cli.Command{
		Name:  "update",
		Args:  "NODE RULE [--action allow|deny] [--match tcp/PORT|...] [--from PREFIX]... [--from-anywhere] [--comment TEXT]",
		Short: "Change one rule; fields not given stay as they are",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.StringVar(&action, "action", "", "allow or deny")
			fs.StringVar(&match, "match", "", "tcp/PORT, udp/PORT, a range, icmp or any")
			fs.Var(&from, "from", "source `prefix`; replaces the rule's sources; repeat for more")
			fs.BoolVar(&anywhere, "from-anywhere", false, "match every source")
			fs.StringVar(&comment, "comment", "", "a short note (empty with --comment '' clears it)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 2 {
				return cli.Usagef("update needs a node name and a rule ID, such as: sfcli node firewall update vps1 r3 --from 10.0.0.0/8")
			}
			node, err := nodeArg(args[:1], "firewall update")
			if err != nil {
				return err
			}
			if anywhere && len(from) > 0 {
				return cli.Usagef("--from and --from-anywhere do not go together")
			}
			if !c.Set("action") && !c.Set("match") && len(from) == 0 && !anywhere && !c.Set("comment") {
				return cli.Usagef("update needs at least one of --action, --match, --from, --from-anywhere, --comment")
			}
			v, err := firewallNow(c, g, s, node)
			if err != nil {
				return err
			}
			rule, ok := findFirewallRule(v, args[1])
			if !ok {
				return fmt.Errorf("%s has no firewall rule %s", node, args[1])
			}
			if c.Set("action") {
				rule.Action = action
			}
			if c.Set("match") {
				if rule.Proto, rule.Ports, err = parseFirewallProto(match); err != nil {
					return err
				}
			}
			if len(from) > 0 {
				rule.From = from
			}
			if anywhere {
				rule.From = nil
			}
			if c.Set("comment") {
				rule.Comment = comment
			}
			return firewallChange(c, g, s, id, node, v.Revision, firewall.Delta{Update: []firewall.Rule{rule}})
		}),
	}
}

func nodeFirewallRemoveCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	return &cli.Command{
		Name:  "remove",
		Args:  "NODE RULE...",
		Short: "Remove rules by ID",
		Flags: func(fs *flag.FlagSet) { fs.Var(&id, "id", "operation `ID` (default: a new one)") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) < 2 {
				return cli.Usagef("remove needs a node name and rule IDs, such as: sfcli node firewall remove vps1 r3")
			}
			node, err := nodeArg(args[:1], "firewall remove")
			if err != nil {
				return err
			}
			v, err := firewallNow(c, g, s, node)
			if err != nil {
				return err
			}
			return firewallChange(c, g, s, id, node, v.Revision, firewall.Delta{Delete: args[1:]})
		}),
	}
}

func nodeFirewallPolicyCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	return &cli.Command{
		Name:  "policy",
		Args:  "NODE inherit|return|drop",
		Short: "Set what happens to traffic no rule matches: follow the cluster (inherit), return to the server's own INPUT rules, or drop",
		Flags: func(fs *flag.FlagSet) { fs.Var(&id, "id", "operation `ID` (default: a new one)") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 2 || args[1] != firewall.PolicyReturn && args[1] != firewall.PolicyDrop && args[1] != firewall.PolicyInherit {
				return cli.Usagef("policy needs a node name and inherit, return or drop")
			}
			node, err := nodeArg(args[:1], "firewall policy")
			if err != nil {
				return err
			}
			v, err := firewallNow(c, g, s, node)
			if err != nil {
				return err
			}
			if v.Policy == args[1] {
				fmt.Fprintf(c.Out, "the policy of %s is already %s\n", node, args[1])
				return nil
			}
			cluster := firewall.NewCluster()
			if v.Cluster != nil {
				cluster = *v.Cluster
			}
			next := firewall.State{Policy: args[1]}
			if firewall.Effective(next, cluster) == firewall.PolicyDrop && v.Effective != firewall.PolicyDrop {
				allows := false
				for _, r := range append(append([]firewall.Rule{}, v.Rules...), cluster.Rules...) {
					allows = allows || r.Action == "allow"
				}
				if !allows {
					fmt.Fprintf(c.Err, "%s has no allow rule: with drop only the locked rules (SFCP, keep_open, ingress) stay open.\n", node)
					if err := g.Prompter(c).Confirm("Drop everything else?"); err != nil {
						return err
					}
				}
			}
			return firewallChange(c, g, s, id, node, v.Revision, firewall.Delta{Policy: args[1]})
		}),
	}
}

func nodeFirewallLogCommand(g *globals) *cli.Command {
	var before uint64
	return &cli.Command{
		Name:  "log",
		Args:  "NODE [--before REVISION]",
		Short: "Show earlier firewall changes on a server, newest first",
		Flags: func(fs *flag.FlagSet) {
			fs.Uint64Var(&before, "before", 0, "only changes before this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			node, err := nodeArg(args, "firewall log")
			if err != nil {
				return err
			}
			r, err := firewallCall(c, g, s, control.NodeFirewallOp{Node: node, Action: "log", After: before})
			if err != nil {
				return err
			}
			if r.Code != "" {
				return fmt.Errorf("%s: %s", r.Code, r.Error)
			}
			if r.View != nil && !r.View.Managed {
				return errors.New("sfcd does not control the firewall of " + node)
			}
			return cli.Print(c.Out, g.output.Format(), r, func() cli.Rows {
				rows := cli.Rows{Header: []string{"revision", "at", "user", "change"}}
				for _, ch := range r.Log {
					rows.Add(strconv.FormatUint(ch.To, 10), time.Unix(ch.At, 0).Format(time.RFC3339), ch.User, firewallDeltaText(ch.Delta, ch.Added))
				}
				if r.More && len(r.Log) > 0 {
					rows.Add("…", "", "", fmt.Sprintf("more: --before %d", r.Log[len(r.Log)-1].To))
				}
				return rows
			})
		}),
	}
}

func firewallDeltaText(d firewall.Delta, added []string) string {
	parts := []string{}
	for i, a := range d.Add {
		if i < len(added) {
			a.ID = added[i]
		}
		parts = append(parts, "add "+a.ID+" "+a.Action+" "+firewallRuleText(a))
	}
	for _, u := range d.Update {
		parts = append(parts, "update "+u.ID+" "+u.Action+" "+firewallRuleText(u))
	}
	for _, id := range d.Delete {
		parts = append(parts, "remove "+id)
	}
	if d.Policy != "" {
		parts = append(parts, "policy "+d.Policy)
	}
	return strings.Join(parts, "; ")
}
