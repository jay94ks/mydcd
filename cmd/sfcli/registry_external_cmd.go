// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagesource"
	"github.com/jay94ks/seafield/internal/secrets"
)

// sfcli registry external: approved external image sources (Docker Hub, a
// company registry, ...) and the reader that pulls through them.

func externalCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "external",
		Short: "External image sources apps may pull from",
		Sub: []*cli.Command{
			{Name: "list", Short: "List external sources", Run: g.withSession(externalList(g))},
			{Name: "show", Args: "NAME", Short: "Show one external source", Run: g.withSession(externalShow(g))},
			externalAddCommand(g),
			externalBindCommand(g),
			externalSelectionCommand(g, "unbind", "unbind-external-registry", "Stop the source's reader"),
			externalSelectionCommand(g, "remove", "delete-external-registry", "Remove an external source"),
			externalCheckCommand(g),
			{Name: "pulls", Short: "Show recent pulls through external sources", Run: g.withSession(externalPulls(g))},
		},
	}
}

func init() {
	opKinds["registry-bind"] = func(g *globals) cli.Handler {
		return changeHandler(g, func(c *cli.Context, s *session, op control.UserOperation) error {
			return bindApprovals(c, g, s, op, true, groupPasswordFDs{})
		}, false)
	}
}

func readExternalRows(ctx context.Context, s *session, tenant string) ([]control.ExternalRegistryView, error) {
	var rows []control.ExternalRegistryView
	var root uint64
	after := ""
	for {
		reply, err := s.Client.ExternalRegistryPage(ctx, s.Target, s.Stored.Session, tenant, after)
		if err != nil {
			return nil, err
		}
		if reply.Tenant != tenant || len(reply.ExternalRegistries) > 8 || after != "" && reply.ExternalRegistriesRootRevision != root {
			return nil, errors.New("external sources changed while reading; run the command again")
		}
		root = reply.ExternalRegistriesRootRevision
		previous := after
		for _, row := range reply.ExternalRegistries {
			if row.Spec.Validate() != nil || row.Spec.Tenant != tenant || row.Revision == 0 || row.Spec.Key() <= after {
				return nil, errors.New("the server sent an invalid external source")
			}
			rows = append(rows, row)
			after = row.Spec.Key()
		}
		if reply.ExternalRegistriesNext == "" {
			return rows, nil
		}
		if len(rows) > 4096 || after <= previous || reply.ExternalRegistriesNext != after {
			return nil, errors.New("the server sent an invalid external source cursor")
		}
	}
}

func findExternalRow(ctx context.Context, s *session, tenant, name string) (*control.ExternalRegistryView, error) {
	rows, err := readExternalRows(ctx, s, tenant)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Spec.ID == name && !rows[i].Deleted {
			return &rows[i], nil
		}
	}
	return nil, nil
}

func externalReader(row control.ExternalRegistryView) string {
	switch {
	case row.Reader == nil:
		return ""
	case row.Reader.Draining:
		return row.Reader.Node + " (stopping)"
	}
	return row.Reader.Node
}

func externalList(g *globals) func(*cli.Context, *session, []string) error {
	return func(c *cli.Context, s *session, args []string) error {
		if len(args) != 0 {
			return cli.Usagef("list takes no arguments")
		}
		tenant, err := g.Tenant(s, true)
		if err != nil {
			return err
		}
		ctx, cancel := g.Deadline(c)
		defer cancel()
		rows, err := readExternalRows(ctx, s, tenant)
		if err != nil {
			return err
		}
		live := slices.DeleteFunc(rows, func(r control.ExternalRegistryView) bool { return r.Deleted })
		return cli.Print(c.Out, g.output.Format(), live, func() cli.Rows {
			t := cli.Rows{Header: []string{"name", "authority", "repository", "auth", "enabled", "reader"}}
			for _, r := range live {
				t.Add(r.Spec.ID, r.Spec.Authority, r.Spec.Repository, r.Spec.Auth, r.Spec.Enabled, externalReader(r))
			}
			return t
		})
	}
}

func externalShow(g *globals) func(*cli.Context, *session, []string) error {
	return func(c *cli.Context, s *session, args []string) error {
		name, err := oneName(args, "source name")
		if err != nil {
			return err
		}
		tenant, err := g.Tenant(s, true)
		if err != nil {
			return err
		}
		ctx, cancel := g.Deadline(c)
		defer cancel()
		row, err := findExternalRow(ctx, s, tenant, name)
		if err != nil {
			return err
		}
		if row == nil {
			return fmt.Errorf("no external source %q in tenant %s", name, tenant)
		}
		return cli.Print(c.Out, g.output.Format(), row, nil)
	}
}

// secretRef reads "[REALM/]ID": no REALM is the tenant's own Vault tree,
// an empty one ("/ID") the cluster's.
func secretRef(v, tenant string) (realm, id string) {
	if r, i, ok := strings.Cut(v, "/"); ok {
		return r, i
	}
	return tenant, v
}

// checkSecretRef says plainly when a source names a Vault secret or key that
// does not exist, instead of a later bind failing with "denied".
func checkSecretRef(ctx context.Context, s *session, flagName, realm, id string, keys ...string) error {
	t, err := readVaultTree(ctx, s, realm)
	if err != nil {
		return fmt.Errorf("%s %s: cannot read the Vault tree of %s: %w", flagName, id, realmName(realm), err)
	}
	o, ok := t.object(id)
	if !ok || o.Kind != secrets.Secret {
		return fmt.Errorf("%s: %s has no secret %s (create it with 'sfcli secret create'; write REALM/ID for another tree, /ID for the cluster's)", flagName, realmName(realm), id)
	}
	for _, k := range keys {
		if !slices.Contains(o.Reference.Keys, k) {
			return fmt.Errorf("%s: secret %s in %s has no key %s (its keys: %s)", flagName, id, realmName(realm), k, strings.Join(o.Reference.Keys, ", "))
		}
	}
	return nil
}

func externalAddCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var rev cli.RevisionFlag
	var authority, repository, auth, secret, userKey, passKey, ca, caKey string
	var disabled bool
	return &cli.Command{
		Name:  "add",
		Args:  "NAME",
		Short: "Add or update an external source",
		Long: `Adds an external image source, or updates one with the same name. The
authority and repository of a name cannot change. Credentials are Vault
values (sfcli secret): --secret names the secret, --username-key and
--password-key its keys.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.Var(&rev, "if-revision", "only if the source is still at this `revision`")
			fs.StringVar(&authority, "authority", "", "registry host[:port], such as docker.io (required)")
			fs.StringVar(&repository, "repository", "**", "repositories allowed: a path, prefix/** or **")
			fs.StringVar(&auth, "auth", "none", "none, password or token")
			fs.StringVar(&secret, "secret", "", "Vault secret `[REALM/]ID` with the credential")
			fs.StringVar(&userKey, "username-key", "username", "key of the user name in --secret")
			fs.StringVar(&passKey, "password-key", "password", "key of the password or token in --secret")
			fs.StringVar(&ca, "ca", "", "Vault secret `[REALM/]ID` with a private CA certificate")
			fs.StringVar(&caKey, "ca-key", "ca.crt", "key of the certificate in --ca")
			fs.BoolVar(&disabled, "disabled", false, "add it switched off")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "source name")
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			spec := imagesource.Source{Tenant: tenant, ID: name, Authority: authority, Repository: repository, Enabled: !disabled, Auth: auth}
			if secret != "" {
				realm, sid := secretRef(secret, tenant)
				spec.Credential = &imagesource.Credential{Realm: realm, ID: sid, UsernameKey: userKey, PasswordKey: passKey}
			}
			if ca != "" {
				realm, sid := secretRef(ca, tenant)
				spec.CA = &imagesource.CertificateAuthority{Realm: realm, ID: sid, Key: caKey}
			}
			if spec.Validate() != nil {
				return cli.Usagef("invalid source: --authority host[:port], --repository a path, prefix/** or **, --auth none|password|token, and --secret only (and always) with password or token")
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			if r := spec.Credential; r != nil {
				if err = checkSecretRef(ctx, s, "--secret", r.Realm, r.ID, r.UsernameKey, r.PasswordKey); err != nil {
					return err
				}
			}
			if r := spec.CA; r != nil {
				if err = checkSecretRef(ctx, s, "--ca", r.Realm, r.ID, r.Key); err != nil {
					return err
				}
			}
			cur, err := findExternalRow(ctx, s, tenant, name)
			if err != nil {
				return err
			}
			verb := "Add"
			if cur != nil {
				if cur.Spec.Authority != authority || cur.Spec.Repository != repository {
					return fmt.Errorf("source %s is %s/%s; the authority and repository of a name cannot change", name, cur.Spec.Authority, cur.Spec.Repository)
				}
				verb = "Update"
			}
			expected, err := rev.Resolve(func() (uint64, error) {
				if cur == nil {
					return 0, nil
				}
				return cur.Revision, nil
			})
			if err != nil {
				return err
			}
			if cur != nil {
				fmt.Fprintf(c.Err, "%s external source %s (%s/%s).\n", verb, name, authority, repository)
				if err = g.Prompter(c).Confirm(verb + " it?"); err != nil {
					return err
				}
			}
			opID := id.Get()
			if _, err = g.send(c, s, change{Summary: "registry external add " + name, ID: opID, Action: "put-external-registry", Expected: expected, Payload: control.ExternalRegistryPut{Spec: spec}}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "external source %s saved (%s)\n", name, opID)
			return nil
		}),
	}
}

// bindApprovals asks for the Group passwords a bind needs, as an app
// deployment does. resume is true when an earlier attempt may have staged
// approvals.
func bindApprovals(c *cli.Context, g *globals, s *session, origin control.UserOperation, resume bool, passwords groupPasswordFDs) error {
	tenant, err := g.Tenant(s, true)
	if err != nil {
		return err
	}
	ctx, cancel := g.Deadline(c)
	defer cancel()
	var sel control.ExternalRegistryBind
	if err := json.Unmarshal(origin.Change.Payload, &sel); err != nil {
		return err
	}
	row, err := findExternalRow(ctx, s, tenant, sel.ID)
	if err != nil {
		return err
	}
	if row == nil || !row.Spec.Enabled || control.ExternalRegistryDefinition(row.Spec) != sel.Definition {
		return errors.New("the source changed after the bind was prepared; run 'sfcli registry external bind' again")
	}
	var realms []string
	for _, ref := range row.Spec.References() {
		if !slices.Contains(realms, ref.Realm) {
			realms = append(realms, ref.Realm)
		}
	}
	slices.Sort(realms)
	o := composeOptions{noInput: g.noInput, passwordFDs: passwords}
	if resume {
		o.method = "resume"
	}
	return ensureAppApprovalRealms(ctx, o, origin.RequestID, origin, tenant, s.Home, s.Client, s.Target, s.Stored, c.Err, realms, nil)
}

// bindBlocker says why a bind cannot start, from what the user can read,
// before the server answers a bare "denied".
func bindBlocker(ctx context.Context, s *session, tenant, name, node string) error {
	row, err := findExternalRow(ctx, s, tenant, name)
	if err != nil {
		return err
	}
	switch {
	case row == nil:
		return fmt.Errorf("no external source %q in tenant %s", name, tenant)
	case !row.Spec.Enabled:
		return fmt.Errorf("source %s is switched off; add it again without --disabled first", name)
	case row.Reader != nil && row.Reader.Draining:
		return fmt.Errorf("source %s is still stopping its reader on %s; bind again once 'sfcli registry external list' shows no reader", name, row.Reader.Node)
	case row.Reader != nil && row.Reader.Node == node:
		return fmt.Errorf("source %s already reads through %s", name, node)
	case row.Reader != nil:
		return fmt.Errorf("source %s already reads through %s, and a source has one reader; run 'sfcli registry external unbind %s' first", name, row.Reader.Node, name)
	}
	// The node list may need more rights than the bind; skip it if unreadable.
	if d, err := readNodes(ctx, s); err == nil {
		v, ok := d.view(node)
		if !ok {
			return fmt.Errorf("no server %s in the cluster", node)
		}
		if !v.AdmitsWork {
			return fmt.Errorf("server %s does not take work now (phase %s); see 'sfcli node show %s'", node, v.Node.Phase, node)
		}
	}
	return nil
}

func externalBindCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var rev cli.RevisionFlag
	var node string
	var passwords groupPasswordFDs
	return &cli.Command{
		Name:  "bind",
		Args:  "NAME --node NODE",
		Short: "Start the source's reader on a server",
		Long: `Starts the reader that pulls through this source on --node. A source has
one reader; unbind it before moving it to another server. If the source uses
protected Vault secrets, their Group passwords are asked for on the terminal,
or read from --group-password-fd in scripts.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.Var(&rev, "if-revision", "only if the source is still at this `revision`")
			fs.StringVar(&node, "node", "", "server that runs the reader (required)")
			fs.Var(&passwords, "group-password-fd", "for scripts: read the password of `REALM/GROUP=FD` (cluster: /GROUP) from that open file descriptor (repeat)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "source name")
			if err != nil {
				return err
			}
			q := control.ExternalRegistryBindQuery{ID: name, Node: node}
			if !q.Valid() {
				return cli.Usagef("--node must name a server")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			if err = bindBlocker(ctx, s, tenant, name, node); err != nil {
				return err
			}
			plan, err := s.Client.PlanExternalRegistryBind(ctx, s.Target, s.Stored.Session, tenant, q)
			if err != nil {
				return fmt.Errorf("%w: binding %s to %s needs Deploy and ManageRegistry on that server in tenant %s, and the tenant must allow the server", err, name, node, tenant)
			}
			expected, err := rev.Resolve(func() (uint64, error) { return plan.Expected, nil })
			if err != nil {
				return err
			}
			opID := id.Get()
			ch := change{Kind: "registry-bind", Summary: "registry external bind " + name + " --node " + node, ID: opID, Action: "bind-external-registry", Expected: expected, Epoch: plan.Epoch, Payload: plan.Selection}
			ch.Before = func(origin control.UserOperation) error { return bindApprovals(c, g, s, origin, false, passwords) }
			if _, err = g.send(c, s, ch); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "external source %s reads through %s (%s)\n", name, node, opID)
			return nil
		}),
	}
}

func externalSelectionCommand(g *globals, verb, action, short string) *cli.Command {
	var id cli.IDFlag
	var rev cli.RevisionFlag
	return &cli.Command{
		Name:  verb,
		Args:  "NAME",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.Var(&rev, "if-revision", "only if the source is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "source name")
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			row, err := findExternalRow(ctx, s, tenant, name)
			if err != nil {
				return err
			}
			if row == nil {
				return fmt.Errorf("no external source %q in tenant %s", name, tenant)
			}
			if verb == "unbind" && (row.Reader == nil || row.Reader.Draining) {
				return fmt.Errorf("source %s has no running reader", name)
			}
			expected, err := rev.Resolve(func() (uint64, error) { return row.Revision, nil })
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "%s: %s %s. Apps can no longer pull through it.\n", short, name, row.Spec.Authority)
			if err = g.Prompter(c).Confirm("Go ahead?"); err != nil {
				return err
			}
			opID := id.Get()
			if _, err = g.send(c, s, change{Summary: "registry external " + verb + " " + name, ID: opID, Action: action, Expected: expected, Payload: control.RegistrySelection{Tenant: tenant, ID: name}}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "%s %s done (%s)\n", verb, name, opID)
			return nil
		}),
	}
}

func externalCheckCommand(g *globals) *cli.Command {
	var image string
	return &cli.Command{
		Name:  "check",
		Args:  "NAME",
		Short: "Log in to the source and optionally read one image",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&image, "image", "", "also read this image's manifest and layers")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "source name")
			if err != nil {
				return err
			}
			q := control.ExternalRegistryProbeQuery{ID: name, Image: image}
			if !q.Valid() {
				return cli.Usagef("--image must be an image reference of this source")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			row, err := findExternalRow(ctx, s, tenant, name)
			if err != nil {
				return err
			}
			switch {
			case row == nil:
				return fmt.Errorf("no external source %q in tenant %s", name, tenant)
			case !row.Spec.Enabled:
				return fmt.Errorf("source %s is switched off", name)
			case row.Reader == nil || row.Reader.Draining:
				return fmt.Errorf("source %s has no running reader; run 'sfcli registry external bind %s --node NODE' first", name, name)
			}
			result, err := s.Client.ProbeExternalRegistry(ctx, s.Target, s.Stored.Session, tenant, q)
			if err != nil {
				return err
			}
			if err = cli.Print(c.Out, g.output.Format(), result, func() cli.Rows {
				t := cli.Rows{Header: []string{"source", "result", "image"}}
				pinned := ""
				if result.Image != nil {
					pinned = result.Image.Pinned
				}
				t.Add(name, result.Code, pinned)
				return t
			}); err != nil {
				return err
			}
			if result.Code != "OK" {
				if hint := probeHint(result.Code); hint != "" {
					fmt.Fprintln(c.Err, hint)
				}
				return cli.ExitError{Code: 3}
			}
			return nil
		}),
	}
}

// probeHint explains the codes people meet first.
func probeHint(code string) string {
	switch code {
	case "PLAIN_HTTP":
		return "The source answers in plain HTTP. Sources are read over HTTPS only; serve it with TLS, and for a private CA add the certificate with --ca."
	case "PLATFORM_MISMATCH":
		return "The image config names another platform, or none (os/architecture empty, as 'crane append' leaves it), than the reader's server."
	case "UNSUPPORTED":
		return "The registry or the manifest media type is not supported (Docker v2 schema 2 and OCI images and indexes are)."
	case "INVALID_CA":
		return "The server certificate does not verify against the --ca certificate (or the system CAs without --ca)."
	case "UNAUTHORIZED", "DENIED":
		return "The registry refused the credential or the repository; check --secret and --repository."
	case "RATE_LIMITED":
		return "The registry refused more reads for now (HTTP 429). Docker Hub limits anonymous pulls per address; add a credential with --auth password, or wait."
	case "UNAVAILABLE", "TIMEOUT":
		return "The reader's server could not reach the registry."
	}
	return ""
}

func externalPulls(g *globals) func(*cli.Context, *session, []string) error {
	return func(c *cli.Context, s *session, args []string) error {
		if len(args) != 0 {
			return cli.Usagef("pulls takes no arguments")
		}
		tenant, err := g.Tenant(s, true)
		if err != nil {
			return err
		}
		ctx, cancel := g.Deadline(c)
		defer cancel()
		var rows []control.RegistryPullView
		var root [32]byte
		after := ""
		for {
			page, err := s.Client.RegistryPulls(ctx, s.Target, s.Stored.Session, tenant, after)
			if err != nil {
				return err
			}
			if after != "" && page.Root != root {
				return errors.New("pulls changed while reading; run the command again")
			}
			root = page.Root
			rows = append(rows, page.Rows...)
			if page.Next == "" {
				break
			}
			if page.Next == after || len(rows) > 65536 {
				return errors.New("the server sent an invalid pull page cursor")
			}
			after = page.Next
		}
		if len(rows) == 0 && g.output.Format() == cli.Table {
			fmt.Fprintln(c.Err, "No pulls yet. A row appears when an app deployment pulls an image through a source; 'check' does not count.")
		}
		return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
			t := cli.Rows{Header: []string{"source", "authority", "node", "stage", "result", "stale"}}
			for _, r := range rows {
				t.Add(r.Source, r.Authority, r.Node, r.Stage, r.Code, r.Stale)
			}
			return t
		})
	}
}
