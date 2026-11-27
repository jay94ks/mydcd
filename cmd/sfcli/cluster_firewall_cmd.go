// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/firewall"
)

// clusterFirewallCommandTree is `sfcli firewall`: the cluster's default
// policy and shared rules, applied on every server whose node.yaml sets
// firewall.managed, under that server's own rules. Required rules are
// checked before the server's rules, so a server cannot override them.
func clusterFirewallCommandTree(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "firewall",
		Short: "Show or change the cluster firewall every managed server applies (system administrator)",
		Sub: []*cli.Command{
			clusterFirewallShowCommand(g),
			clusterFirewallRuleCommand(g, "allow"),
			clusterFirewallRuleCommand(g, "deny"),
			clusterFirewallUpdateCommand(g),
			clusterFirewallRemoveCommand(g),
			clusterFirewallPolicyCommand(g),
		},
	}
}

func clusterFirewallNow(c *cli.Context, g *globals, s *session) (control.ClusterFirewallView, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	return s.Client.ClusterFirewall(ctx, s.Target, s.Stored.Session)
}

func clusterFirewallChange(c *cli.Context, g *globals, s *session, id cli.IDFlag, summary string, revision uint64, d firewall.Delta) error {
	opID := id.Get()
	if _, err := g.send(c, s, change{Summary: "firewall " + summary, ID: opID, Action: control.ClusterFirewallAction, Expected: revision, Payload: d}); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "cluster firewall changed: revision %d -> %d (%s); every managed server applies it at its next check\n", revision, revision+1, opID)
	return nil
}

func clusterFirewallShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Short: "Show the cluster's default policy and shared rules",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("show takes no arguments")
			}
			v, err := clusterFirewallNow(c, g, s)
			if err != nil {
				return err
			}
			f := v.Firewall
			return cli.Print(c.Out, g.output.Format(), v, func() cli.Rows {
				rows := cli.Rows{Header: []string{"kind", "id", "rule", "note"}}
				rows.Add("policy", "-", firewallPolicyText(f.Policy), fmt.Sprintf("revision %d, %d/%d rules; a server may set its own", f.Revision, len(f.Rules), v.MaxRules))
				clusterFirewallRows(&rows, f.Rules, "")
				return rows
			})
		}),
	}
}

// clusterFirewallRows lists rules in the order a server checks them:
// required deny and allow, then the other deny and allow.
func clusterFirewallRows(rows *cli.Rows, rules []firewall.Rule, prefix string) {
	for _, required := range []bool{true, false} {
		for _, action := range []string{"deny", "allow"} {
			for _, r := range rules {
				if r.Action != action || r.Required != required {
					continue
				}
				kind := prefix + action
				if required {
					kind = prefix + "required " + action
				}
				rows.Add(kind, r.ID, firewallRuleText(r), r.Comment)
			}
		}
	}
}

func firewallPolicyText(p string) string {
	switch p {
	case firewall.PolicyDrop:
		return "drop (unmatched traffic is dropped)"
	case firewall.PolicyInherit:
		return "inherit (follows the cluster)"
	}
	return "return (unmatched traffic goes on to the server's own INPUT rules)"
}

func clusterFirewallRuleCommand(g *globals, action string) *cli.Command {
	var id cli.IDFlag
	var from listFlag
	var comment string
	var required bool
	short := "Let traffic in on every managed server"
	if action == "deny" {
		short = "Drop traffic on every managed server"
	}
	return &cli.Command{
		Name:  action,
		Args:  "tcp/PORT|udp/PORT|icmp|any [--from PREFIX]... [--required]",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&from, "from", "source `prefix` such as 192.168.1.0/24; repeat for more (default: anywhere)")
			fs.StringVar(&comment, "comment", "", "a short note")
			fs.BoolVar(&required, "required", false, "checked before every server's own rules, so no server can override it")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("%s needs what to match, such as: sfcli firewall %s tcp/22 --from 192.168.1.0/24 --required", action, action)
			}
			proto, ports, err := parseFirewallProto(args[0])
			if err != nil {
				return err
			}
			v, err := clusterFirewallNow(c, g, s)
			if err != nil {
				return err
			}
			r := firewall.Rule{Action: action, Proto: proto, Ports: ports, From: from, Comment: comment, Required: required}
			return clusterFirewallChange(c, g, s, id, action+" "+firewallRuleText(r), v.Firewall.Revision, firewall.Delta{Add: []firewall.Rule{r}})
		}),
	}
}

func clusterFirewallUpdateCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var from listFlag
	var action, match, comment string
	var anywhere, required bool
	return &cli.Command{
		Name:  "update",
		Args:  "RULE [--action allow|deny] [--match tcp/PORT|...] [--from PREFIX]... [--from-anywhere] [--required=true|false] [--comment TEXT]",
		Short: "Change one cluster rule; fields not given stay as they are",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.StringVar(&action, "action", "", "allow or deny")
			fs.StringVar(&match, "match", "", "tcp/PORT, udp/PORT, a range, icmp or any")
			fs.Var(&from, "from", "source `prefix`; replaces the rule's sources; repeat for more")
			fs.BoolVar(&anywhere, "from-anywhere", false, "match every source")
			fs.BoolVar(&required, "required", false, "whether servers may override the rule (false: they may)")
			fs.StringVar(&comment, "comment", "", "a short note (empty with --comment '' clears it)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("update needs a rule ID, such as: sfcli firewall update c2 --required")
			}
			if anywhere && len(from) > 0 {
				return cli.Usagef("--from and --from-anywhere do not go together")
			}
			if !c.Set("action") && !c.Set("match") && len(from) == 0 && !anywhere && !c.Set("comment") && !c.Set("required") {
				return cli.Usagef("update needs at least one of --action, --match, --from, --from-anywhere, --required, --comment")
			}
			v, err := clusterFirewallNow(c, g, s)
			if err != nil {
				return err
			}
			var rule firewall.Rule
			found := false
			for _, r := range v.Firewall.Rules {
				if r.ID == args[0] {
					rule, found = r, true
				}
			}
			if !found {
				return fmt.Errorf("the cluster firewall has no rule %s", args[0])
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
			if c.Set("required") {
				rule.Required = required
			}
			if c.Set("comment") {
				rule.Comment = comment
			}
			return clusterFirewallChange(c, g, s, id, "update "+rule.ID, v.Firewall.Revision, firewall.Delta{Update: []firewall.Rule{rule}})
		}),
	}
}

func clusterFirewallRemoveCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	return &cli.Command{
		Name:  "remove",
		Args:  "RULE...",
		Short: "Remove cluster rules by ID",
		Flags: func(fs *flag.FlagSet) { fs.Var(&id, "id", "operation `ID` (default: a new one)") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) == 0 {
				return cli.Usagef("remove needs rule IDs, such as: sfcli firewall remove c3")
			}
			v, err := clusterFirewallNow(c, g, s)
			if err != nil {
				return err
			}
			return clusterFirewallChange(c, g, s, id, "remove "+strings.Join(args, " "), v.Firewall.Revision, firewall.Delta{Delete: args})
		}),
	}
}

func clusterFirewallPolicyCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	return &cli.Command{
		Name:  "policy",
		Args:  "return|drop",
		Short: "Set the default for traffic no rule matches; servers that inherit follow it",
		Flags: func(fs *flag.FlagSet) { fs.Var(&id, "id", "operation `ID` (default: a new one)") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || args[0] != firewall.PolicyReturn && args[0] != firewall.PolicyDrop {
				return cli.Usagef("policy needs return or drop")
			}
			v, err := clusterFirewallNow(c, g, s)
			if err != nil {
				return err
			}
			if v.Firewall.Policy == args[0] {
				fmt.Fprintf(c.Out, "the cluster policy is already %s\n", args[0])
				return nil
			}
			if args[0] == firewall.PolicyDrop {
				fmt.Fprintln(c.Err, "Every managed server that inherits the policy will drop traffic no rule takes; only the locked rules (SFCP, keep_open such as SSH, ingress) and allow rules stay open.")
				if err := g.Prompter(c).Confirm("Drop everything else on those servers?"); err != nil {
					return err
				}
			}
			return clusterFirewallChange(c, g, s, id, "policy "+args[0], v.Firewall.Revision, firewall.Delta{Policy: args[0]})
		}),
	}
}
