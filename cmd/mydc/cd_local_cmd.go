// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// cd field / put-local / clear-local: one field's Git and current values,
// and the services added next to the Git file (docs/cli/cd.md).

func cdFieldCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "field",
		Args:  "APP FIELD",
		Short: "Show one field's value in Git, what runs now and any override",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 2 {
				return cli.Usagef("field needs APP and FIELD")
			}
			app, err := cdAppArg(args[:1], "field", 0)
			if err != nil {
				return err
			}
			path, err := cdFieldPath(args[1])
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			view, err := s.Client.AppDeliveryField(ctx, s.Target, s.Stored.Session, tenant, control.AppCDFieldRequest{App: app, Path: path})
			cancel()
			if err != nil {
				return err
			}
			if g.output.Format() != cli.Table {
				return cli.Print(c.Out, g.output.Format(), view, nil)
			}
			fmt.Fprintf(c.Out, "Field:      %s\n", strings.Join(view.Path, "/"))
			if v := view.Values; v != nil {
				fmt.Fprintf(c.Out, "Git:        %s\nCurrent:    %s (%s)\n", string(v.Source.Value), string(v.Current.Value), v.CurrentOrigin)
			}
			if view.Override != nil {
				fmt.Fprintf(c.Out, "Override:   by %s (revision %d)\n", view.Override.Actor, view.Override.Revision)
			}
			return nil
		}),
	}
}

// localUploadID names the upload of one put-local operation; it is the same
// for every retry of that operation ID.
func localUploadID(tenant, app, user, id string) string {
	raw, _ := json.Marshal([]string{tenant, app, user, id})
	digest := sha256.Sum256(append([]byte("mydc-local-upload-1\x00"), raw...))
	return "local-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]))
}

func readLocalServices(c *cli.Context, path, app string) ([]byte, []string, error) {
	body, err := readInputFile(c, path, deployment.ArtifactMaxBytes)
	if err != nil {
		return nil, nil, err
	}
	input, err := deployment.ParseApp(body)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	if input.Name != "" && input.Name != app {
		return nil, nil, fmt.Errorf("%s names another app", path)
	}
	var names []string
	for name := range input.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	if len(names) == 0 || len(names) > 128 {
		return nil, nil, fmt.Errorf("%s needs 1 to 128 services", path)
	}
	return body, names, nil
}

func cdLocalCommand(g *globals, verb string) *cli.Command {
	var file string
	var id cli.IDFlag
	var revision cli.RevisionFlag
	short := "Add services that run next to the Git file (replaces earlier ones)"
	if verb == "clear-local" {
		short = "Remove the services added with put-local at the next sync"
	}
	return &cli.Command{
		Name:  verb,
		Args:  "APP",
		Short: short,
		Long: short + `. The change becomes part of the next candidate;
'mydc cd sync' or approve starts it. Running containers are not touched before then.`,
		Flags: func(fs *flag.FlagSet) {
			if verb == "put-local" {
				fs.StringVar(&file, "f", "", "app.yaml-style `file` with only the added services")
			}
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the CD record is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, err := cdAppArg(args, verb, 0)
			if err != nil {
				return err
			}
			if done, err := g.savedChange(c, s, id.String(), "cd "+verb+" "+app, "put-app-local-services", "clear-app-local-services"); done {
				return err
			}
			if verb == "put-local" && file == "" {
				return cli.Usagef("put-local needs -f FILE")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			row, err := cdApp(c, g, s, tenant, app)
			if err != nil {
				return err
			}
			v := row.CD
			if v.LocalTarget == ([32]byte{}) {
				return fmt.Errorf("app %s has no deployment to add services to yet", app)
			}
			opID := id.Get()
			if len(opID) > 50 {
				return cli.Usagef("--id for %s is at most 50 characters (each upload part gets its own ID)", verb)
			}
			q := control.AppLocalChange{Tenant: tenant, App: app, Registration: v.Registration, Revision: v.LocalRevision}
			expected, _ := revision.Resolve(func() (uint64, error) { return v.Revision, nil })
			if revision.String() == "" {
				t := v.LocalTarget
				q.Target = &t
			}
			action, impact := "clear-app-local-services", fmt.Sprintf("Remove the added services of app %s at the next sync.", app)
			if verb == "put-local" {
				body, names, err := readLocalServices(c, file, app)
				if err != nil {
					return err
				}
				action, impact = "put-app-local-services", fmt.Sprintf("Add services %s to app %s at the next sync.", strings.Join(names, ", "), app)
				q.Upload, q.Digest, q.Services = localUploadID(tenant, app, s.Stored.Session.User, opID), sha256.Sum256(body), names
				fmt.Fprintln(c.Err, impact)
				if err := g.Prompter(c).Confirm("Go ahead?"); err != nil {
					return err
				}
				// The file goes up as an app upload first; the change then
				// names the upload by its ID and digest.
				begin := control.AppUploadBegin{Tenant: tenant, App: app, Deployment: row.Deployment, ID: q.Upload, Length: len(body), Digest: q.Digest}
				if _, err := g.send(c, s, change{ID: opID + "-up", Summary: "cd put-local " + app + " (upload)", Action: "begin-app-upload", Payload: begin}); err != nil {
					return err
				}
				for start, index := 0, 0; start < len(body); start, index = start+deployment.ArtifactPartBytes, index+1 {
					part := control.AppUploadPart{Tenant: tenant, ID: q.Upload, Index: index, Data: body[start:min(len(body), start+deployment.ArtifactPartBytes)]}
					if _, err := g.send(c, s, change{ID: fmt.Sprintf("%s-p%03d", opID, index), Summary: fmt.Sprintf("cd put-local %s (part %d)", app, index+1), Action: "put-app-part", Expected: uint64(index + 1), Payload: part}); err != nil {
						return err
					}
				}
				fmt.Fprintf(c.Err, "Operation %s\n", opID)
				result, err := g.send(c, s, change{ID: opID, Summary: "cd put-local " + app, Action: action, Expected: expected, Payload: q})
				if err != nil {
					return err
				}
				return printApplied(c, g, opID, result)
			}
			return g.sendAndPrint(c, s, impact, change{ID: opID, Summary: "cd clear-local " + app, Action: action, Expected: expected, Payload: q})
		}),
	}
}
