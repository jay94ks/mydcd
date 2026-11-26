// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// tenant trust: the registries and repositories a tenant's containers may
// pull images from. An app whose image matches no rule is refused with
// IMAGE_NOT_TRUSTED.
func tenantTrustCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "trust",
		Short: "List and change the image sources a tenant trusts",
		Long: `A rule is REGISTRY/REPOSITORY, or REGISTRY/** for every repository of a
registry. Apps of the tenant may only use images that match a rule.`,
		Sub: []*cli.Command{
			tenantTrustListCommand(g),
			tenantTrustChangeCommand(g, true),
			tenantTrustChangeCommand(g, false),
		},
	}
}

func parseTrustRule(s string) (access.TrustRule, error) {
	registry, repository, found := strings.Cut(s, "/")
	if !found || registry == "" || repository == "" {
		return access.TrustRule{}, cli.Usagef("%q is not REGISTRY/REPOSITORY or REGISTRY/**", s)
	}
	rule := access.TrustRule{Registry: registry, Repository: repository}
	if _, err := access.CanonicalTrust([]access.TrustRule{rule}); err != nil {
		return access.TrustRule{}, cli.Usagef("%q is not a valid image source", s)
	}
	return rule, nil
}

// readTrust reads the tenant's rules and the tenant revision they belong to.
func readTrust(c *cli.Context, g *globals, s *session, tenant string) ([]access.TrustRule, uint64, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	reply, err := s.Client.PublicRead(ctx, s.Target, s.Stored.Session, "image-trust", tenant, control.PublicReadQuery{}, "")
	if err != nil {
		return nil, 0, err
	}
	if reply.PublicRead == nil {
		return nil, 0, fmt.Errorf("no image trust reply for tenant %s", tenant)
	}
	return slices.Clone(reply.PublicRead.Rules), reply.PublicRead.TenantRevision, nil
}

func trustText(r access.TrustRule) string { return r.Registry + "/" + r.Repository }

func tenantTrustListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Args:  "TENANT",
		Short: "List the image sources a tenant trusts",
		Run: func(c *cli.Context, args []string) error {
			tenant, err := tenantArg(args, "TENANT")
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			rules, _, err := readTrust(c, g, s, tenant)
			if err != nil {
				return err
			}
			if rules == nil {
				rules = []access.TrustRule{}
			}
			return cli.Print(c.Out, g.output.Format(), rules, func() cli.Rows {
				t := cli.Rows{Header: []string{"registry", "repository"}}
				for _, r := range rules {
					t.Add(r.Registry, r.Repository)
				}
				return t
			})
		},
	}
}

func tenantTrustChangeCommand(g *globals, add bool) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	name, short := "add", "Trust an image source for a tenant"
	if !add {
		name, short = "remove", "Stop trusting an image source for a tenant"
	}
	return &cli.Command{
		Name:  name,
		Args:  "TENANT REGISTRY/REPOSITORY",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "change only if the tenant is still at this `revision`")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 2 {
				return cli.Usagef("expected TENANT REGISTRY/REPOSITORY")
			}
			tenant, err := tenantArg(args[:1], "TENANT")
			if err != nil {
				return err
			}
			rule, err := parseTrustRule(args[1])
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			rules, current, err := readTrust(c, g, s, tenant)
			if err != nil {
				return err
			}
			rev, err := revision.Resolve(func() (uint64, error) { return current, nil })
			if err != nil {
				return err
			}
			has := slices.Contains(rules, rule)
			switch {
			case add && has:
				fmt.Fprintf(c.Out, "tenant %s already trusts %s\n", tenant, trustText(rule))
				return nil
			case !add && !has:
				fmt.Fprintf(c.Out, "tenant %s does not trust %s\n", tenant, trustText(rule))
				return nil
			case add:
				rules = append(rules, rule)
			default:
				rules = slices.DeleteFunc(rules, func(r access.TrustRule) bool { return r == rule })
			}
			if err = g.Prompter(c).Confirm(fmt.Sprintf("%s %s for tenant %s?", map[bool]string{true: "Trust", false: "Stop trusting"}[add], trustText(rule), tenant)); err != nil {
				return err
			}
			if rules == nil {
				rules = []access.TrustRule{}
			}
			if _, err = g.send(c, s, change{Summary: "tenant trust " + name + " " + tenant + " " + trustText(rule), ID: id.Get(), Action: "set-trust", Expected: rev, Payload: control.TrustAssignment{Tenant: tenant, Rules: rules}}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "tenant %s trust updated\n", tenant)
			return nil
		}),
	}
}
