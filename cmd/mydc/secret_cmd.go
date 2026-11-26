// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/secrets"
)

// The secret group of devel/design/cli-and-formats.md: the Vault tree of a
// tenant (or, with --all, of the cluster), its groups and secrets, value and
// group password writes, and approvals. Values never go on the command
// line or into the op index: they are read from a file, standard input or a
// hidden terminal prompt.

func secretCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "secret",
		Short: "Secrets: the Vault tree, values, group passwords and approvals",
		Long: `Each tenant has one Vault tree of groups and secrets; --all works on the
cluster's own tree (system administrator). A secret points at an object in
an external Vault; 'secret put' writes its values there through the
cluster's writer node. A group password lets apps that use the group's
secrets be approved.`,
		Sub: []*cli.Command{
			secretListCommand(g),
			secretShowCommand(g),
			secretInitCommand(g),
			secretCreateCommand(g),
			secretGroupCommand(g),
			secretPutCommand(g),
			secretACLCommand(g),
			secretMoveCommand(g),
			secretSelectionCommand(g, "revoke", "Stop new uses of a group or secret", "vault-revoke"),
			secretSelectionCommand(g, "retire", "Remove a revoked group or secret that nothing uses", "vault-retire"),
			secretUsagesCommand(g),
			secretWriteCommand(g),
			secretApprovalCommand(g),
			secretProfileCommand(g),
			secretIssuerCommand(g),
		},
	}
}

// vaultScope is --all: the cluster's Vault tree instead of the tenant's.
type vaultScope struct{ all bool }

func (v *vaultScope) register(fs *flag.FlagSet) {
	fs.BoolVar(&v.all, "all", false, "the cluster's Vault tree (system administrator)")
}

// realm is the Vault realm: the tenant, or "" for the cluster.
func (v vaultScope) realm(g *globals, s *session) (string, error) {
	if v.all {
		if g.tenant != "" {
			return "", cli.Usagef("--all and --tenant cannot be used together")
		}
		return "", nil
	}
	return g.Tenant(s, true)
}

func realmName(realm string) string {
	if realm == "" {
		return "the cluster"
	}
	return "tenant " + realm
}

func scopeSummary(realm string) string {
	if realm == "" {
		return " --all"
	}
	return " --tenant " + realm
}

// vaultTree is one consistent read of a Vault tree.
type vaultTree struct {
	rows                                   []control.VaultView
	tree, epoch, approvals, root, revision uint64
}

func (t vaultTree) object(id string) (secrets.Object, bool) {
	for _, r := range t.rows {
		if r.Object != nil && r.Object.ID == id {
			return *r.Object, true
		}
	}
	return secrets.Object{}, false
}

func (t vaultTree) write(id string) (control.VaultWriteView, bool) {
	for _, r := range t.rows {
		if r.Write != nil && r.Write.Request.ID == id {
			return *r.Write, true
		}
	}
	return control.VaultWriteView{}, false
}

func readVaultTree(ctx context.Context, s *session, realm string) (vaultTree, error) {
	var t vaultTree
	cursor := ""
	for {
		page, err := s.Client.QueryVault(ctx, s.Target, s.Stored.Session, realm, cursor)
		if err != nil {
			return t, err
		}
		if cursor == "" {
			t.root, t.tree, t.epoch, t.approvals, t.revision = page.VaultRootRevision, page.VaultTreeRevision, page.VaultWriteEpoch, page.VaultApprovalRevision, page.VaultRevision
		} else if page.VaultRootRevision != t.root {
			return t, errors.New("the Vault tree changed while it was read; try again")
		}
		t.rows = append(t.rows, page.Vault...)
		if page.VaultNext == "" {
			return t, nil
		}
		if page.VaultNext <= cursor || len(t.rows) > 1<<16 {
			return t, mydcp.ErrAdmission
		}
		cursor = page.VaultNext
	}
}

// vaultObject reads the tree and finds one object, for a change on it.
func (g *globals) vaultObject(c *cli.Context, s *session, realm, id string) (vaultTree, secrets.Object, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	t, err := readVaultTree(ctx, s, realm)
	if err != nil {
		return t, secrets.Object{}, err
	}
	o, ok := t.object(id)
	if !ok {
		return t, o, fmt.Errorf("%s has no group or secret %s", realmName(realm), id)
	}
	return t, o, nil
}

// secretSession checks the words first, then opens the session and picks the
// realm.
func (g *globals) secretSession(c *cli.Context, v vaultScope) (*session, string, error) {
	s, err := g.open(c)
	if err != nil {
		return nil, "", err
	}
	realm, err := v.realm(g, s)
	if err != nil {
		s.Close()
		return nil, "", err
	}
	return s, realm, nil
}

func validSecretID(kind, id string) error {
	if !lifecycle.ValidID(id) {
		return cli.Usagef("%q is not a %s name (lower-case letters, digits and '-', starting with a letter)", id, kind)
	}
	return nil
}

func secretArgs(args []string, n int, usage string) error {
	if len(args) != n {
		return cli.Usagef("%s", usage)
	}
	for _, a := range args {
		if err := validSecretID("group or secret", a); err != nil {
			return err
		}
	}
	return nil
}

// vaultChange confirms and sends one Vault metadata change; the server
// finishes it when it applies it.
func (g *globals) vaultChange(c *cli.Context, s *session, f *changeFlags, impact, summary, action string, expected uint64, payload any) error {
	ok, err := g.confirm(c, f, impact)
	if !ok || err != nil {
		return err
	}
	return g.syncChange(c, s, f, summary, action, expected, payload)
}

func secretListCommand(g *globals) *cli.Command {
	var v vaultScope
	return &cli.Command{
		Name:  "list",
		Short: "List the groups and secrets of the Vault tree",
		Flags: v.register,
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			t, err := readVaultTree(ctx, s, realm)
			cancel()
			if err != nil {
				return err
			}
			objects := []secrets.Object{}
			for _, r := range t.rows {
				if r.Object != nil {
					objects = append(objects, *r.Object)
				}
			}
			return cli.Print(c.Out, g.output.Format(), objects, func() cli.Rows {
				rows := cli.Rows{Header: []string{"name", "kind", "parent", "status", "keys", "pending-write"}}
				for _, o := range objects {
					rows.Add(o.ID, o.Kind, o.Parent, o.Status, strings.Join(o.Reference.Keys, ","), o.PendingWrite)
				}
				return rows
			})
		},
	}
}

func secretShowCommand(g *globals) *cli.Command {
	var v vaultScope
	return &cli.Command{
		Name:  "show",
		Args:  "NAME",
		Short: "Show one group or secret",
		Flags: v.register,
		Run: func(c *cli.Context, args []string) error {
			if err := secretArgs(args, 1, "show needs one group or secret name"); err != nil {
				return err
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			_, o, err := g.vaultObject(c, s, realm, args[0])
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), o, nil)
		},
	}
}

func secretInitCommand(g *globals) *cli.Command {
	var v vaultScope
	var f changeFlags
	return &cli.Command{
		Name:  "init",
		Args:  "ROOT",
		Short: "Create the Vault tree with its root group",
		Flags: func(fs *flag.FlagSet) { v.register(fs); f.register(fs, false, true) },
		Run: func(c *cli.Context, args []string) error {
			if err := secretArgs(args, 1, "init needs the root group name"); err != nil {
				return err
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			return g.vaultChange(c, s, &f, fmt.Sprintf("Create the Vault tree of %s with root group %s.", realmName(realm), args[0]),
				"secret init "+args[0]+scopeSummary(realm), "vault-init", 0, control.VaultRealm{Realm: realm, Root: args[0]})
		},
	}
}

func secretCreateCommand(g *globals) *cli.Command {
	var v vaultScope
	var f changeFlags
	var parent, profile, object string
	var keys stringList
	return &cli.Command{
		Name:  "create",
		Args:  "NAME",
		Short: "Add a secret that points at an object in the external Vault",
		Long: `Adds a secret under a group. --object is the full path of the object
inside the Vault mount that the writer profile --profile reaches, and must
start with that profile's prefix in the writer node's node.yaml (for example
values/shop/db under prefix values/shop); --key names each value in it. The
values are written later with 'mydc secret put'. Only the writer node knows
its prefix: a path outside it makes 'put' end as notapplied, writing nothing.`,
		Flags: func(fs *flag.FlagSet) {
			v.register(fs)
			f.register(fs, false, true)
			fs.StringVar(&parent, "parent", "", "the `group` it goes under")
			fs.StringVar(&profile, "profile", "", "writer `profile` that stores its values")
			fs.StringVar(&object, "object", "", "`path` of the object in the external Vault")
			fs.Var(&keys, "key", "value `name` in the object (repeat)")
		},
		Run: func(c *cli.Context, args []string) error {
			if err := secretArgs(args, 1, "create needs one secret name"); err != nil {
				return err
			}
			if err := validSecretID("group", parent); err != nil {
				return cli.Usagef("create needs --parent GROUP")
			}
			if profile == "" || object == "" || len(keys) == 0 {
				return cli.Usagef("create needs --profile, --object and at least one --key")
			}
			for _, k := range keys {
				if err := validSecretKey(k); err != nil {
					return err
				}
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			t, err := readVaultTree(ctx, s, realm)
			cancel()
			if err != nil {
				return err
			}
			sorted := slices.Clone([]string(keys))
			slices.Sort(sorted)
			payload := control.VaultObject{Realm: realm, Object: secrets.Object{ID: args[0], Parent: parent, Kind: secrets.Secret, Reference: secrets.Reference{Profile: profile, Object: object, Keys: sorted}}}
			return g.vaultChange(c, s, &f, fmt.Sprintf("Add secret %s under %s in %s, with keys %s.", args[0], parent, realmName(realm), strings.Join(sorted, ", ")),
				"secret create "+args[0]+scopeSummary(realm), "vault-create", t.tree, payload)
		},
	}
}

func secretGroupCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "group",
		Short: "Groups: create, set the password, order and approval age",
		Sub: []*cli.Command{
			secretGroupCreateCommand(g),
			secretPasswordCommand(g),
			secretReorderCommand(g),
			secretApprovalAgeCommand(g),
		},
	}
}

func secretGroupCreateCommand(g *globals) *cli.Command {
	var v vaultScope
	var f changeFlags
	var parent string
	return &cli.Command{
		Name:  "create",
		Args:  "NAME",
		Short: "Add a group",
		Flags: func(fs *flag.FlagSet) {
			v.register(fs)
			f.register(fs, false, true)
			fs.StringVar(&parent, "parent", "", "the `group` it goes under")
		},
		Run: func(c *cli.Context, args []string) error {
			if err := secretArgs(args, 1, "group create needs one group name"); err != nil {
				return err
			}
			if validSecretID("group", parent) != nil {
				return cli.Usagef("group create needs --parent GROUP")
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			t, err := readVaultTree(ctx, s, realm)
			cancel()
			if err != nil {
				return err
			}
			return g.vaultChange(c, s, &f, fmt.Sprintf("Add group %s under %s in %s.", args[0], parent, realmName(realm)),
				"secret group create "+args[0]+scopeSummary(realm), "vault-create", t.tree,
				control.VaultObject{Realm: realm, Object: secrets.Object{ID: args[0], Parent: parent, Kind: secrets.Group}})
		},
	}
}

func secretReorderCommand(g *globals) *cli.Command {
	var v vaultScope
	var f changeFlags
	return &cli.Command{
		Name:  "reorder",
		Args:  "GROUP ENTRY...",
		Short: "Set the order of the groups and secrets in a group",
		Long:  `Lists every entry of the group in the new order. Apps take a value from the first entry that has it.`,
		Flags: func(fs *flag.FlagSet) { v.register(fs); f.register(fs, false, true) },
		Run: func(c *cli.Context, args []string) error {
			if len(args) < 2 {
				return cli.Usagef("reorder needs the group and its entries in order")
			}
			if err := secretArgs(args, len(args), ""); err != nil {
				return err
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			_, o, err := g.vaultObject(c, s, realm, args[0])
			if err != nil {
				return err
			}
			return g.vaultChange(c, s, &f, fmt.Sprintf("Order group %s as %s.", args[0], strings.Join(args[1:], ", ")),
				"secret group reorder "+args[0]+scopeSummary(realm), "vault-reorder", o.Revision, control.VaultOrder{Realm: realm, ID: args[0], Entries: args[1:]})
		},
	}
}

func secretApprovalAgeCommand(g *globals) *cli.Command {
	var v vaultScope
	var f changeFlags
	return &cli.Command{
		Name:  "approval-age",
		Args:  "GROUP AGE",
		Short: "Set how long an approval with the group password lasts, such as 720h",
		Flags: func(fs *flag.FlagSet) { v.register(fs); f.register(fs, false, true) },
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 2 {
				return cli.Usagef("approval-age needs the group and an age such as 720h")
			}
			if err := validSecretID("group", args[0]); err != nil {
				return err
			}
			age, err := time.ParseDuration(args[1])
			if err != nil || age < time.Second || age%time.Second != 0 {
				return cli.Usagef("the age must be whole seconds, such as 24h or 720h")
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			_, o, err := g.vaultObject(c, s, realm, args[0])
			if err != nil {
				return err
			}
			return g.vaultChange(c, s, &f, fmt.Sprintf("Approvals with the password of group %s last %s.", args[0], age),
				"secret group approval-age "+args[0]+" "+age.String()+scopeSummary(realm), "vault-approval-age", o.Revision, control.VaultAge{Realm: realm, ID: args[0], Seconds: int64(age / time.Second)})
		},
	}
}

func secretACLCommand(g *globals) *cli.Command {
	var v vaultScope
	var f changeFlags
	var users, services, denyUsers, denyServices, tenants stringList
	var clear bool
	return &cli.Command{
		Name:  "acl",
		Args:  "NAME",
		Short: "Set who may use a group or secret",
		Long: `Each option given replaces that list; lists not given stay as they are.
--clear empties every list first. A service is written APP/SERVICE.`,
		Flags: func(fs *flag.FlagSet) {
			v.register(fs)
			f.register(fs, false, true)
			fs.Var(&users, "allow-user", "`user` that may use it (repeat)")
			fs.Var(&services, "allow-service", "`APP/SERVICE` that may use it (repeat)")
			fs.Var(&denyUsers, "deny-user", "`user` that may not use it (repeat)")
			fs.Var(&denyServices, "deny-service", "`APP/SERVICE` that may not use it (repeat)")
			fs.Var(&tenants, "grant-tenant", "with --all, `tenant` that may use it (repeat)")
			fs.BoolVar(&clear, "clear", false, "start from empty lists")
		},
		Run: func(c *cli.Context, args []string) error {
			if err := secretArgs(args, 1, "acl needs one group or secret name"); err != nil {
				return err
			}
			set := map[string]bool{}
			c.Flags.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
			if !clear && !set["allow-user"] && !set["allow-service"] && !set["deny-user"] && !set["deny-service"] && !set["grant-tenant"] {
				return cli.Usagef("acl needs at least one of --allow-user, --allow-service, --deny-user, --deny-service, --grant-tenant or --clear")
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			_, o, err := g.vaultObject(c, s, realm, args[0])
			if err != nil {
				return err
			}
			a := o.ACL
			if clear {
				a = secrets.ACL{}
			}
			for name, list := range map[string]*[]string{"allow-user": &a.Users, "allow-service": &a.Services, "deny-user": &a.DenyUsers, "deny-service": &a.DenyServices, "grant-tenant": &a.TenantGrants} {
				if set[name] {
					values := map[string]stringList{"allow-user": users, "allow-service": services, "deny-user": denyUsers, "deny-service": denyServices, "grant-tenant": tenants}[name]
					*list = slices.Clone([]string(values))
					slices.Sort(*list)
				}
			}
			impact := fmt.Sprintf("Set who may use %s: users %s; services %s; denied users %s; denied services %s.", args[0], listText(a.Users), listText(a.Services), listText(a.DenyUsers), listText(a.DenyServices))
			if len(a.TenantGrants) > 0 {
				impact += " Tenants: " + listText(a.TenantGrants) + "."
			}
			return g.vaultChange(c, s, &f, impact, "secret acl "+args[0]+scopeSummary(realm), "vault-acl", o.Revision, control.VaultACL{Realm: realm, ID: args[0], ACL: a})
		},
	}
}

func listText(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ", ")
}

func secretMoveCommand(g *globals) *cli.Command {
	var v vaultScope
	var f changeFlags
	var parent string
	return &cli.Command{
		Name:  "move",
		Args:  "NAME",
		Short: "Move a group or secret under another group",
		Flags: func(fs *flag.FlagSet) {
			v.register(fs)
			f.register(fs, false, true)
			fs.StringVar(&parent, "parent", "", "the new `group`")
		},
		Run: func(c *cli.Context, args []string) error {
			if err := secretArgs(args, 1, "move needs one group or secret name"); err != nil {
				return err
			}
			if validSecretID("group", parent) != nil {
				return cli.Usagef("move needs --parent GROUP")
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			_, o, err := g.vaultObject(c, s, realm, args[0])
			if err != nil {
				return err
			}
			return g.vaultChange(c, s, &f, fmt.Sprintf("Move %s from %s to %s.", args[0], o.Parent, parent),
				"secret move "+args[0]+" --parent "+parent+scopeSummary(realm), "vault-move", o.Revision, control.VaultMove{Realm: realm, ID: args[0], Parent: parent})
		},
	}
}

func secretSelectionCommand(g *globals, name, short, action string) *cli.Command {
	var v vaultScope
	var f changeFlags
	return &cli.Command{
		Name:  name,
		Args:  "NAME",
		Short: short,
		Flags: func(fs *flag.FlagSet) { v.register(fs); f.register(fs, false, true) },
		Run: func(c *cli.Context, args []string) error {
			if err := secretArgs(args, 1, name+" needs one group or secret name"); err != nil {
				return err
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			_, o, err := g.vaultObject(c, s, realm, args[0])
			if err != nil {
				return err
			}
			impact := fmt.Sprintf("Revoke %s %s: nothing new may use it; running apps keep what they have until they stop.", o.Kind, args[0])
			if name == "retire" {
				impact = fmt.Sprintf("Remove %s %s from the tree. The external Vault object is not deleted.", o.Kind, args[0])
			}
			return g.vaultChange(c, s, &f, impact, "secret "+name+" "+args[0]+scopeSummary(realm), action, o.Revision, control.VaultSelection{Realm: realm, ID: args[0]})
		},
	}
}

func secretUsagesCommand(g *globals) *cli.Command {
	var v vaultScope
	return &cli.Command{
		Name:  "usages",
		Args:  "NAME",
		Short: "List the apps and services that use a group or secret",
		Flags: v.register,
		Run: func(c *cli.Context, args []string) error {
			if err := secretArgs(args, 1, "usages needs one group or secret name"); err != nil {
				return err
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			rows, err := readPublicRows(ctx, s, "vault-usages", realm, control.PublicReadQuery{Name: args[0]})
			cancel()
			if err != nil {
				return err
			}
			uses := []secrets.PublicUsage{}
			for _, r := range rows {
				if r.SecretUsage != nil {
					uses = append(uses, *r.SecretUsage)
				}
			}
			return cli.Print(c.Out, g.output.Format(), uses, func() cli.Rows {
				t := cli.Rows{Header: []string{"app", "service", "node", "user", "live", "secrets"}}
				for _, u := range uses {
					app := u.App
					if u.Standalone != "" {
						app = u.Standalone + " (standalone)"
					}
					t.Add(app, u.Service, u.Node, u.User, u.Live, strings.Join(u.Secrets, ","))
				}
				return t
			})
		},
	}
}

func secretApprovalCommand(g *globals) *cli.Command {
	var v vaultScope
	var app string
	return &cli.Command{
		Name:  "approvals",
		Short: "List the group password approvals of apps",
		Flags: func(fs *flag.FlagSet) {
			v.register(fs)
			fs.StringVar(&app, "app", "", "only this `app`")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("approvals takes no arguments")
			}
			s, realm, err := g.secretSession(c, v)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			rows, err := readPublicRows(ctx, s, "vault-approvals", realm, control.PublicReadQuery{App: app})
			cancel()
			if err != nil {
				return err
			}
			list := []secrets.PublicApproval{}
			for _, r := range rows {
				if r.Approval != nil {
					list = append(list, *r.Approval)
				}
			}
			return cli.Print(c.Out, g.output.Format(), list, func() cli.Rows {
				t := cli.Rows{Header: []string{"id", "group", "app", "user", "expires", "in-use", "revoking"}}
				for _, a := range list {
					app := a.App
					if a.Standalone != "" {
						app = a.Standalone + " (standalone)"
					}
					t.Add(a.ID, a.Group, app, a.User, time.Unix(a.ExpiresAt, 0).Local().Format("2006-01-02 15:04"), a.Consumers, a.Revoking)
				}
				return t
			})
		},
		Sub: []*cli.Command{secretApprovalRevokeCommand(g)},
	}
}

func secretApprovalRevokeCommand(g *globals) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  "revoke",
		Args:  "ID",
		Short: "Take back one approval (the approval realm's secret manager)",
		Long:  `Apps that use the approval may not start again with it. Take the ID from 'mydc secret approvals'.`,
		Flags: func(fs *flag.FlagSet) { f.register(fs, false, true) },
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 1 || args[0] == "" || len(args[0]) > 128 {
				return cli.Usagef("approvals revoke needs one approval ID")
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			realm, _ := g.Tenant(s, false)
			ctx, cancel := g.Deadline(c)
			t, err := readVaultTree(ctx, s, realm)
			cancel()
			if err != nil {
				return err
			}
			return g.vaultChange(c, s, &f, fmt.Sprintf("Revoke approval %s.", args[0]), "secret approvals revoke "+args[0], "vault-revoke-approval", t.approvals, control.VaultApprovalSelection{ID: args[0]})
		},
	}
}

func secretProfileCommand(g *globals) *cli.Command {
	var v vaultScope
	var f changeFlags
	var node string
	var values, verifiers, disable bool
	return &cli.Command{
		Name:  "profile",
		Short: "Writer profiles: which node writes values to the external Vault",
		Sub: []*cli.Command{{
			Name:  "set",
			Args:  "PROFILE",
			Short: "Set which node writes through a profile (system administrator)",
			Long: `The node needs the profile's external Vault settings in its node.yaml.
--values lets it write secret values, --verifiers group passwords.`,
			Flags: func(fs *flag.FlagSet) {
				v.register(fs)
				f.register(fs, false, true)
				fs.StringVar(&node, "node", "", "the writer `node`")
				fs.BoolVar(&values, "values", false, "writes secret values")
				fs.BoolVar(&verifiers, "verifiers", false, "writes group passwords")
				fs.BoolVar(&disable, "disable", false, "stop writing through this profile")
			},
			Run: func(c *cli.Context, args []string) error {
				if len(args) != 1 || validSecretKey(args[0]) != nil {
					return cli.Usagef("profile set needs one profile name")
				}
				if node == "" || !values && !verifiers {
					return cli.Usagef("profile set needs --node and --values or --verifiers")
				}
				s, realm, err := g.secretSession(c, v)
				if err != nil {
					return err
				}
				defer s.Close()
				ctx, cancel := g.Deadline(c)
				defer cancel()
				key, err := memberKey(ctx, s, node)
				if err != nil {
					return err
				}
				t, err := readVaultTree(ctx, s, realm)
				if err != nil {
					return err
				}
				if t.tree == 0 {
					return fmt.Errorf("%s has no Vault tree yet; run mydc secret init first", realmName(realm))
				}
				p := secrets.WriteProfile{ID: args[0], Node: node, Key: key, Enabled: !disable, Values: values, Verifiers: verifiers}
				what := []string{}
				if values {
					what = append(what, "secret values")
				}
				if verifiers {
					what = append(what, "group passwords")
				}
				impact := fmt.Sprintf("Profile %s of %s: node %s writes %s.", args[0], realmName(realm), node, strings.Join(what, " and "))
				if disable {
					impact = fmt.Sprintf("Profile %s of %s on node %s stops writing.", args[0], realmName(realm), node)
				}
				return g.vaultChange(c, s, &f, impact, "secret profile set "+args[0]+" --node "+node+scopeSummary(realm), "vault-set-profile", t.tree, control.VaultProfile{Realm: realm, Profile: p})
			},
		}},
	}
}

func secretIssuerCommand(g *globals) *cli.Command {
	issuer := func(name string, enabled bool, short string) *cli.Command {
		var f changeFlags
		return &cli.Command{
			Name:  name,
			Args:  "NODE",
			Short: short,
			Flags: func(fs *flag.FlagSet) { f.register(fs, false, true) },
			Run: func(c *cli.Context, args []string) error {
				if len(args) != 1 || !lifecycle.ValidID(args[0]) {
					return cli.Usagef("issuer %s needs one node name", name)
				}
				s, err := g.open(c)
				if err != nil {
					return err
				}
				defer s.Close()
				ctx, cancel := g.Deadline(c)
				defer cancel()
				key, err := memberKey(ctx, s, args[0])
				if err != nil {
					return err
				}
				realm, _ := g.Tenant(s, false)
				t, err := readVaultTree(ctx, s, realm)
				if err != nil {
					return err
				}
				impact := fmt.Sprintf("Node %s checks group passwords and signs approvals.", args[0])
				if !enabled {
					impact = fmt.Sprintf("Node %s stops signing approvals.", args[0])
				}
				return g.vaultChange(c, s, &f, impact, "secret issuer "+name+" "+args[0], "vault-set-issuer", t.approvals, control.VaultIssuer{Key: key, Enabled: enabled})
			},
		}
	}
	return &cli.Command{
		Name:  "issuer",
		Short: "Nodes that sign group password approvals (system administrator)",
		Sub: []*cli.Command{
			issuer("enable", true, "Let a node sign approvals"),
			issuer("disable", false, "Stop a node signing approvals"),
		},
	}
}

// memberKey is the cluster key of a node.
func memberKey(ctx context.Context, s *session, node string) ([32]byte, error) {
	after := ""
	for range 256 {
		reply, err := s.Client.Query(ctx, s.Target, s.Stored.Session, "members", after)
		if err != nil {
			return [32]byte{}, err
		}
		for _, m := range reply.Members {
			if m.Peer.ID == node {
				return identity.ParseKey(m.Peer.Key)
			}
		}
		if reply.MembersNext == "" || reply.MembersNext <= after {
			break
		}
		after = reply.MembersNext
	}
	return [32]byte{}, fmt.Errorf("no node %s in the cluster", node)
}

// stringList is a repeatable option.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error {
	if v == "" || slices.Contains(*l, v) || len(*l) >= 128 {
		return errors.New("empty, repeated or too many values")
	}
	*l = append(*l, v)
	return nil
}

func validSecretKey(k string) error {
	if k == "" || k == "." || k == ".." || len(k) > 128 {
		return cli.Usagef("%q is not a key name", k)
	}
	for _, b := range []byte(k) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-' || b == '.') {
			return cli.Usagef("%q is not a key name (letters, digits, '_', '-' and '.')", k)
		}
	}
	return nil
}
