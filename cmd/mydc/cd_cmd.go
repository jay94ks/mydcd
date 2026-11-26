// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// mydc cd: apps that follow a Git branch. The policy is cd.yaml, kept by the
// server (`cd set`); app.yaml in Git is what gets deployed. Usage:
// docs/cli/cd.md.

func cdCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "cd",
		Short: "Deploy apps from a Git branch",
		Long: `An app with a CD policy follows one file (app.yaml) in a Git branch. New
commits become candidates; with sync: manual a person approves each one,
with sync: auto it is deployed when it passes the checks.`,
		Sub: []*cli.Command{
			cdShowCommand(g),
			cdSetCommand(g),
			cdProbeCommand(g),
			cdSyncCommand(g),
			cdDecisionCommand(g, "approve"),
			cdDecisionCommand(g, "reject"),
			cdToggleCommand(g, "pause"),
			cdToggleCommand(g, "resume"),
			cdAbandonCommand(g),
			cdReplanCommand(g),
			cdHistoryCommand(g),
			cdDiffCommand(g),
			cdOverrideCommand(g),
			cdReleaseCommand(g),
			cdFieldCommand(g),
			cdLocalCommand(g, "put-local"),
			cdLocalCommand(g, "clear-local"),
			cdApproverCommand(g, "add"),
			cdApproverCommand(g, "remove"),
		},
	}
}

func cdAppArg(args []string, verb string, extra int) (string, error) {
	if len(args) < 1 || len(args) > 1+extra || !lifecycle.ValidID(args[0]) {
		return "", cli.Usagef("%s needs an app name", verb)
	}
	return args[0], nil
}

// cdApp reads the app's CD view from the app list.
func cdApp(c *cli.Context, g *globals, s *session, tenant, app string) (control.AppView, error) {
	row, err := cdAppRow(c, g, s, tenant, app)
	if err == nil && row.CD == nil {
		return row, fmt.Errorf("app %s has no CD policy; set one with 'mydc cd set %s -f cd.yaml'", app, app)
	}
	return row, err
}

// cdAppRow reads the app's row from the app list, with or without CD.
func cdAppRow(c *cli.Context, g *globals, s *session, tenant, app string) (control.AppView, error) {
	after := ""
	for range 4096 {
		ctx, cancel := g.Deadline(c)
		page, err := s.Client.AppPage(ctx, s.Target, s.Stored.Session, tenant, after)
		cancel()
		if err != nil {
			return control.AppView{}, err
		}
		for _, row := range page.Apps {
			if row.Tenant == tenant && row.App == app {
				return row, nil
			}
		}
		if page.AppsNext == "" || page.AppsNext <= after {
			break
		}
		after = page.AppsNext
	}
	return control.AppView{}, fmt.Errorf("app %q not found in tenant %s", app, tenant)
}

// cdStatus is `cd show` for scripts: the policy as cd.yaml plus the state.
type cdStatus struct {
	Tenant    string                        `json:"tenant"`
	App       string                        `json:"app"`
	Policy    deployment.CDFile             `json:"policy"`
	Revision  uint64                        `json:"revision"`
	Paused    bool                          `json:"paused"`
	Status    *deployment.DeliveryStatus    `json:"status,omitempty"`
	Candidate *deployment.DeliverySelection `json:"candidate,omitempty"`
	Running   *deployment.DeliverySelection `json:"running,omitempty"`
	Error     string                        `json:"source_error,omitempty"`
	Health    string                        `json:"health,omitempty"`
	View      *control.AppCDView            `json:"detail"`
}

func cdShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "APP",
		Short: "Show an app's CD policy, candidate and what is running",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, err := cdAppArg(args, "show", 0)
			if err != nil {
				return err
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
			out := cdStatus{Tenant: tenant, App: app, Policy: deployment.CDFileOf(v.Policy), Revision: v.Revision, Paused: v.Paused, Status: v.Status, Candidate: v.Candidate, Running: v.Running, Error: v.SourceError, Health: row.Health, View: v}
			if g.output.Format() != cli.Table {
				return cli.Print(c.Out, g.output.Format(), out, nil)
			}
			p := out.Policy
			fmt.Fprintf(c.Out, "App:        %s/%s\nSource:     %s %s:%s\nSync:       %s (drift: %s)\n", tenant, app, p.Repository, p.Branch, p.Path, p.Sync, p.Drift)
			state := "following"
			if v.Paused {
				state = "paused"
			}
			fmt.Fprintf(c.Out, "State:      %s\n", state)
			if v.Running != nil {
				fmt.Fprintf(c.Out, "Running:    %s\n", shortCommit(v.Running.Commit))
			}
			if v.Candidate != nil {
				fmt.Fprintf(c.Out, "Candidate:  %s (%s)\n", shortCommit(v.Candidate.Commit), hex.EncodeToString(v.Candidate.Candidate[:]))
			}
			if v.Status != nil && v.Status.Operation != "" {
				fmt.Fprintf(c.Out, "Operation:  %s\n", v.Status.Operation)
			}
			if v.SourceError != "" {
				fmt.Fprintf(c.Out, "Error:      %s\n", v.SourceError)
			}
			if row.Health != "" {
				fmt.Fprintf(c.Out, "Health:     %s\n", row.Health)
			}
			return nil
		}),
	}
}

func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

func readCDFile(c *cli.Context, path string) (deployment.DeliveryDeclaration, error) {
	raw, err := readInputFile(c, path, 32<<10)
	if err != nil {
		return deployment.DeliveryDeclaration{}, err
	}
	p, err := deployment.ParseCDFile(raw)
	if err != nil {
		return p, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// cdTarget is the execution target CAS of a CD change: the change applies
// only while the app still runs what was read. --if-revision asks for the
// stricter CD record revision instead.
func cdTarget(v *control.AppCDView, revision *cli.RevisionFlag) (*[32]byte, uint64, error) {
	if revision.String() != "" {
		n, _ := revision.Resolve(nil)
		return nil, n, nil
	}
	if v.Target == ([32]byte{}) {
		return nil, 0, errors.New("the app has no deployment to compare with yet; pass --if-revision with the CD revision from 'mydc cd show -o yaml'")
	}
	t := v.Target
	return &t, v.Revision, nil
}

func cdSetCommand(g *globals) *cli.Command {
	var file string
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "set",
		Args:  "APP",
		Short: "Replace an app's CD policy with cd.yaml",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "f", "", "cd.yaml `file`")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the CD record is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, err := cdAppArg(args, "set", 0)
			if err != nil {
				return err
			}
			if done, err := g.savedChange(c, s, id.String(), "cd set "+app, "configure-app-cd"); done {
				return err
			}
			if file == "" {
				return cli.Usagef("set needs -f cd.yaml")
			}
			policy, err := readCDFile(c, file)
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			row, err := cdAppRow(c, g, s, tenant, app)
			if err != nil {
				return err
			}
			var q control.AppCDChange
			var expected uint64
			if row.CD == nil {
				// The first policy turns CD on; the app's own revision guards it.
				expected, err = revision.Resolve(func() (uint64, error) { return row.Revision, nil })
				q = control.AppCDChange{Tenant: tenant, App: app, Policy: &policy}
			} else {
				var target *[32]byte
				target, expected, err = cdTarget(row.CD, &revision)
				q = control.AppCDChange{Tenant: tenant, App: app, Policy: &policy, PolicyRevision: row.CD.PolicyRevision, Target: target}
			}
			if err != nil {
				return err
			}
			impact := fmt.Sprintf("App %s follows %s %s:%s (sync %s).", app, policy.Source.Repository, policy.Source.Ref, policy.Source.Path, deployment.CDFileOf(policy).Sync)
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "cd set " + app, Action: "configure-app-cd", Expected: expected, Payload: q})
		}),
	}
}

func cdProbeCommand(g *globals) *cli.Command {
	var file string
	return &cli.Command{
		Name:  "probe",
		Args:  "APP",
		Short: "Check that the server can read the file cd.yaml points to",
		Long:  "Fetches the branch head once and reports the commit and size. Nothing is changed.",
		Flags: func(fs *flag.FlagSet) { fs.StringVar(&file, "f", "", "cd.yaml `file`") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, err := cdAppArg(args, "probe", 0)
			if err != nil {
				return err
			}
			if file == "" {
				return cli.Usagef("probe needs -f cd.yaml")
			}
			policy, err := readCDFile(c, file)
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			q := deployment.GitProbeRequest{App: app, Repository: policy.Source.Repository, Branch: policy.Source.Ref, Path: policy.Source.Path, Credential: policy.Source.Credential}
			if !q.Valid() {
				return fmt.Errorf("%s: repository must be https without a user name, branch a branch name", file)
			}
			ctx, cancel := g.Deadline(c)
			result, err := s.Client.ProbeCD(ctx, s.Target, s.Stored.Session, tenant, q)
			cancel()
			if err != nil {
				return err
			}
			if err = cli.Print(c.Out, g.output.Format(), result, func() cli.Rows {
				t := cli.Rows{Header: []string{"result", "commit", "size", "node"}}
				code := result.Code
				if code == "" {
					code = "ok"
				}
				t.Add(code, shortCommit(result.Commit), result.Size, result.Node)
				return t
			}); err != nil {
				return err
			}
			if result.Code != "" {
				return cli.ExitError{Code: 3}
			}
			return nil
		}),
	}
}

func cdSyncCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var candidate string
	var recover bool
	return &cli.Command{
		Name:  "sync",
		Args:  "APP",
		Short: "Deploy the current candidate now",
		Long: `Deploys the app's current candidate commit. The operation ID is also the
deployment operation; follow it with 'mydc cd show APP'. --recover deploys
the candidate again over a failed or half-finished deployment.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&candidate, "candidate", "", "only if the candidate is still this `digest` (from cd show)")
			fs.BoolVar(&recover, "recover", false, "redeploy over a failed deployment")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the CD record is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, err := cdAppArg(args, "sync", 0)
			if err != nil {
				return err
			}
			if done, err := g.savedChange(c, s, id.String(), "cd sync "+app, "sync-app", "recover-app"); done {
				return err
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
			if v.Candidate == nil {
				return errors.New("there is no candidate to deploy; check the source with 'mydc cd show " + app + "'")
			}
			if candidate != "" && hex.EncodeToString(v.Candidate.Candidate[:]) != candidate {
				return errors.New("the candidate changed; check it with 'mydc cd show " + app + "'")
			}
			target, expected, err := cdTarget(v, &revision)
			if err != nil {
				return err
			}
			opID := id.Get()
			if deployment.ResourceKey("task", tenant, app, opID) == "" {
				return cli.Usagef("--id %q cannot name a deployment", opID)
			}
			action, verb := "sync-app", "Deploy"
			if recover {
				action, verb = "recover-app", "Redeploy"
			}
			q := control.AppCDChange{Tenant: tenant, App: app, Target: target, Choice: &control.AppDeliveryChoice{Operation: opID, Candidate: v.Candidate.Candidate, Registration: v.Registration}}
			impact := fmt.Sprintf("%s commit %s to app %s.", verb, shortCommit(v.Candidate.Commit), app)
			summary := "cd sync " + app
			if recover {
				summary += " --recover"
			}
			return g.sendAndPrint(c, s, impact, change{ID: opID, Summary: summary, Action: action, Expected: expected, Payload: q})
		}),
	}
}

func parseDigest(text string) ([32]byte, error) {
	var d [32]byte
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != text {
		return d, cli.Usagef("%q is not a candidate digest (64 hex characters from cd show)", text)
	}
	copy(d[:], raw)
	return d, nil
}

// cdDecisionCommand is approve and reject of a candidate (sync: manual).
// approve --secrets instead gives the Secret Group approvals a CD
// deployment waits for.
func cdDecisionCommand(g *globals, verb string) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	var secrets bool
	var operation string
	var passwords groupPasswordFDs
	short := "Approve the app's candidate commit for deployment"
	if verb == "reject" {
		short = "Reject the app's candidate commit"
	}
	return &cli.Command{
		Name:  verb,
		Args:  "APP [CANDIDATE]",
		Short: short,
		Long:  short + ". CANDIDATE (from cd show) makes sure the approved commit is the one you looked at.",
		Flags: func(fs *flag.FlagSet) {
			if verb == "approve" {
				fs.BoolVar(&secrets, "secrets", false, "give the Secret Group approvals the deployment waits for")
				fs.StringVar(&operation, "operation", "", "with --secrets: the deployment `operation` (default: the candidate's)")
				fs.Var(&passwords, "group-password-fd", "with --secrets, for scripts: read the password of `REALM/GROUP=FD` from that open file descriptor (repeat)")
			}
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the CD record is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, err := cdAppArg(args, verb, 1)
			if err != nil {
				return err
			}
			if !secrets {
				if done, err := g.savedChange(c, s, id.String(), "cd "+verb+" "+app, "cd-"+verb); done {
					return err
				}
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			if secrets {
				return cdApproveSecrets(c, g, s, tenant, app, args[1:], operation, passwords)
			}
			row, err := cdApp(c, g, s, tenant, app)
			if err != nil {
				return err
			}
			v := row.CD
			if v.Candidate == nil {
				return errors.New("there is no candidate to " + verb)
			}
			if len(args) == 2 {
				want, err := parseDigest(args[1])
				if err != nil {
					return err
				}
				if want != v.Candidate.Candidate {
					return errors.New("the candidate changed; check it with 'mydc cd show " + app + "'")
				}
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return v.Revision, nil })
			q := control.AppCDDecisionChange{Tenant: tenant, App: app, Candidate: v.Candidate.Candidate, Target: v.Target, Strict: revision.String() != ""}
			impact := fmt.Sprintf("%s commit %s of app %s.", strings.ToUpper(verb[:1])+verb[1:], shortCommit(v.Candidate.Commit), app)
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "cd " + verb + " " + app, Action: "cd-" + verb, Expected: expected, Payload: q})
		}),
	}
}

// cdApproveSecrets gives the Secret Group approvals of the CD deployment
// (the passwords are asked on the terminal and never saved).
func cdApproveSecrets(c *cli.Context, g *globals, s *session, tenant, app string, args []string, operation string, passwords groupPasswordFDs) error {
	selection := control.AppApprovalSelection{Operation: operation}
	if operation == "" {
		if len(args) != 1 {
			return cli.Usagef("approve --secrets needs --operation ID or the CANDIDATE digest")
		}
		d, err := parseDigest(args[0])
		if err != nil {
			return err
		}
		selection.Candidate = &d
	}
	ctx, cancel := g.Deadline(c)
	defer cancel()
	registration, err := s.Client.AppDeliveryRegistration(ctx, s.Target, s.Stored.Session, tenant, app, selection)
	if err != nil {
		return err
	}
	var begin control.AppBegin
	if json.Unmarshal(registration.Origin.Change.Payload, &begin) != nil {
		return errors.New("the server returned a bad registration")
	}
	if len(registration.Realms) == 0 {
		fmt.Fprintln(c.Err, "No Secret Group approvals are needed.")
		return nil
	}
	if err := userauth.PrepareComposeApprovals(s.Home, s.Client, s.Stored.Session, begin.Operation); err != nil {
		return err
	}
	o := composeOptions{method: "up", noInput: g.noInput, passwordFDs: passwords}
	if err := ensureAppApprovalRealms(ctx, o, begin.Operation, registration.Origin, tenant, s.Home, s.Client, s.Target, s.Stored, c.Err, registration.Realms, &registration.Selection); err != nil {
		// A wrong password or missing approver exits 3, an unknown outcome 4.
		var problem *composeApprovalFailure
		if errors.As(err, &problem) {
			return cli.ExitError{Code: problem.code, Err: err}
		}
		return err
	}
	return cli.Print(c.Out, g.output.Format(), map[string]any{"tenant": tenant, "app": app, "groups": registration.Realms, "state": "approved"}, nil)
}

// cdApproverCommand: grant-cd-approver / revoke-cd-approver. An approver may
// approve or reject this app's candidates while they can read the tenant,
// without the tenant's CD permission.
func cdApproverCommand(g *globals, verb string) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	short := "Let a tenant member approve or reject this app's candidates"
	action := "grant-cd-approver"
	if verb == "remove" {
		short, action = "Take back an approver of this app", "revoke-cd-approver"
	}
	return &cli.Command{
		Name:  "approver-" + verb,
		Args:  "APP USER",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the CD record is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, err := cdAppArg(args, "approver-"+verb, 1)
			if err != nil {
				return err
			}
			if len(args) != 2 {
				return cli.Usagef("expected APP USER")
			}
			if done, err := g.savedChange(c, s, id.String(), "cd approver-"+verb+" "+app, action); done {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			user, err := cdMemberID(c, g, s, tenant, args[1])
			if err != nil {
				return err
			}
			row, err := cdApp(c, g, s, tenant, app)
			if err != nil {
				return err
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return row.CD.Revision, nil })
			impact := fmt.Sprintf("%s may approve or reject candidates of app %s.", args[1], app)
			if verb == "remove" {
				impact = fmt.Sprintf("%s may no longer approve or reject candidates of app %s.", args[1], app)
			}
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "cd approver-" + verb + " " + app + " " + args[1], Action: action, Expected: expected, Payload: control.AppCDApproverChange{Tenant: tenant, App: app, User: user}})
		}),
	}
}

// cdMemberID finds a tenant member's user ID by user name.
func cdMemberID(c *cli.Context, g *globals, s *session, tenant, username string) (string, error) {
	after := ""
	for range 4096 {
		ctx, cancel := g.Deadline(c)
		reply, err := s.Client.TenantMembersPage(ctx, s.Target, s.Stored.Session, tenant, after)
		cancel()
		if err != nil {
			return "", err
		}
		for _, m := range reply.TenantMembers {
			if m.Username == username {
				return m.User, nil
			}
		}
		if reply.TenantMembersNext == "" || reply.TenantMembersNext == after {
			break
		}
		after = reply.TenantMembersNext
	}
	return "", fmt.Errorf("%s is not a member of tenant %s", username, tenant)
}

func cdToggleCommand(g *globals, verb string) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	short := "Stop following the branch (running containers are kept)"
	if verb == "resume" {
		short = "Follow the branch again"
	}
	return &cli.Command{
		Name:  verb,
		Args:  "APP",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the CD record is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, err := cdAppArg(args, verb, 0)
			if err != nil {
				return err
			}
			if done, err := g.savedChange(c, s, id.String(), "cd "+verb+" "+app, verb+"-app-cd"); done {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			action := verb + "-app-cd"
			ctx, cancel := g.Deadline(c)
			plan, err := s.Client.PlanCDToggle(ctx, s.Target, s.Stored.Session, tenant, control.CDToggleQuery{App: app, Action: action})
			cancel()
			if err != nil {
				return err
			}
			if plan.Paused == (verb == "pause") {
				fmt.Fprintf(c.Err, "App %s is already %sd.\n", app, verb)
				return nil
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return plan.Expected, nil })
			impact := fmt.Sprintf("%s CD of app %s.", strings.ToUpper(verb[:1])+verb[1:], app)
			if plan.ActiveOperation != "" {
				impact += fmt.Sprintf(" Deployment %s keeps running.", plan.ActiveOperation)
			}
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "cd " + verb + " " + app, Action: action, Expected: expected, Epoch: plan.Epoch, Payload: control.AppCDChange{Tenant: tenant, App: app}})
		}),
	}
}

func cdAbandonCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "abandon",
		Args:  "APP",
		Short: "Give up a deployment that cannot finish",
		Long:  "Gives up the app's unfinished CD deployment so a new candidate can be deployed. Containers already replaced stay as they are.",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the CD record is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, err := cdAppArg(args, "abandon", 0)
			if err != nil {
				return err
			}
			if done, err := g.savedChange(c, s, id.String(), "cd abandon "+app, "abandon-app-sync"); done {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			row, err := cdApp(c, g, s, tenant, app)
			if err != nil {
				return err
			}
			expected, _ := revision.Resolve(func() (uint64, error) { return row.CD.Revision, nil })
			return g.sendAndPrint(c, s, fmt.Sprintf("Give up the unfinished deployment of app %s.", app), change{ID: id.Get(), Summary: "cd abandon " + app, Action: "abandon-app-sync", Expected: expected, Payload: control.AppCDChange{Tenant: tenant, App: app}})
		}),
	}
}

func cdHistoryCommand(g *globals) *cli.Command {
	var limit int
	return &cli.Command{
		Name:  "history",
		Args:  "APP",
		Short: "List the commits CD planned and deployed, newest first",
		Flags: func(fs *flag.FlagSet) { fs.IntVar(&limit, "limit", 50, "show at most this many records") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, err := cdAppArg(args, "history", 0)
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			rows := []control.AppCDHistoryRecord{}
			after := ""
			for len(rows) < limit {
				ctx, cancel := g.Deadline(c)
				page, err := s.Client.AppDeliveryHistory(ctx, s.Target, s.Stored.Session, tenant, app, after)
				cancel()
				if err != nil {
					return err
				}
				rows = append(rows, page.Records...)
				if page.Next == "" || page.Next == after {
					break
				}
				after = page.Next
			}
			if len(rows) > limit {
				rows = rows[:limit]
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"planned", "commit", "status", "operation", "by"}}
				for _, r := range rows {
					when := ""
					if r.PlannedAt != 0 {
						when = time.Unix(int64(r.PlannedAt), 0).Local().Format("2006-01-02 15:04")
					}
					status := r.Status
					if r.Code != "" {
						status += " (" + r.Code + ")"
					}
					t.Add(when, shortCommit(r.Commit), status, r.Operation, r.Actor)
				}
				return t
			})
		}),
	}
}

func cdDiffCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "diff",
		Args:  "APP",
		Short: "Show what the candidate changes compared with what is running",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, err := cdAppArg(args, "diff", 0)
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			diff, err := s.Client.AppDeliveryDiff(ctx, s.Target, s.Stored.Session, tenant, app)
			cancel()
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), diff, func() cli.Rows {
				t := cli.Rows{Header: []string{"service", "field", "change"}}
				for _, ch := range diff.Changes {
					t.Add(ch.Service, strings.Join(ch.Path, "/"), ch.Action)
				}
				return t
			})
		}),
	}
}

func cdFieldPath(text string) ([]string, error) {
	path := strings.Split(text, "/")
	if !deployment.AllowedAppOverride(path) {
		return nil, cli.Usagef("%q is not a field CD lets you override (services/SERVICE/FIELD[/KEY])", text)
	}
	return path, nil
}

func cdOverrideCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	return &cli.Command{
		Name:  "override",
		Args:  "APP FIELD VALUE",
		Short: "Keep a field at your value instead of the one in Git",
		Long: `Sets FIELD (services/SERVICE/FIELD[/KEY], such as services/web/environment/LOG_LEVEL)
to VALUE until 'mydc cd release'. VALUE is JSON; a word that is not JSON is
taken as a string.`,
		Flags: func(fs *flag.FlagSet) { fs.Var(&id, "id", "operation `ID` (default: a new one)") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 3 || !lifecycle.ValidID(args[0]) {
				return cli.Usagef("override needs APP FIELD VALUE")
			}
			app := args[0]
			if done, err := g.savedChange(c, s, id.String(), "cd override "+app+" "+args[1], "override-app"); done {
				return err
			}
			path, err := cdFieldPath(args[1])
			if err != nil {
				return err
			}
			value := []byte(args[2])
			if !json.Valid(value) {
				value, _ = json.Marshal(args[2])
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			view, err := cdField(c, g, s, tenant, app, path)
			if err != nil {
				return err
			}
			if len(view.Refs) == 0 || len(view.Refs) > 128 {
				return errors.New("the app's deployment is not settled; try again when it is")
			}
			q := control.AppOverrideChange{Tenant: tenant, App: app, Path: path, Target: &view.Target, Value: value, Refs: view.Refs}
			if view.Override != nil {
				q.Revision = view.Override.Revision
			}
			impact := fmt.Sprintf("Keep %s of app %s at %s.", args[1], app, value)
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "cd override " + app + " " + args[1], Action: "override-app", Expected: view.Revision, Payload: q})
		}),
	}
}

func cdField(c *cli.Context, g *globals, s *session, tenant, app string, path []string) (control.AppCDField, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	view, err := s.Client.AppDeliveryField(ctx, s.Target, s.Stored.Session, tenant, control.AppCDFieldRequest{App: app, Path: path})
	if err == nil && view.Target == ([32]byte{}) {
		err = errors.New("the app has no settled deployment yet")
	}
	return view, err
}

func cdReleaseCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	return &cli.Command{
		Name:  "release",
		Args:  "APP FIELD",
		Short: "Let Git decide a field again",
		Flags: func(fs *flag.FlagSet) { fs.Var(&id, "id", "operation `ID` (default: a new one)") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 2 || !lifecycle.ValidID(args[0]) {
				return cli.Usagef("release needs APP FIELD")
			}
			app := args[0]
			if done, err := g.savedChange(c, s, id.String(), "cd release "+app+" "+args[1], "release-app-override"); done {
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
			view, err := cdField(c, g, s, tenant, app, path)
			if err != nil {
				return err
			}
			if view.Override == nil {
				return fmt.Errorf("%s of app %s is not overridden", args[1], app)
			}
			q := control.AppOverrideChange{Tenant: tenant, App: app, Path: path, Target: &view.Target, Revision: view.Override.Revision}
			return g.sendAndPrint(c, s, fmt.Sprintf("Let Git decide %s of app %s again.", args[1], app), change{ID: id.Get(), Summary: "cd release " + app + " " + args[1], Action: "release-app-override", Expected: view.Revision, Payload: q})
		}),
	}
}

func cdReplanCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "replan",
		Args:  "APP",
		Short: "Plan the current candidate again against the app as it is now",
		Long: `Use it when something outside CD changed the app (a volume move was
cancelled, a node left) and the candidate's plan is out of date. Nothing is
deployed; approve or sync the new plan as usual.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the CD record is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			app, err := cdAppArg(args, "replan", 0)
			if err != nil {
				return err
			}
			if done, err := g.savedChange(c, s, id.String(), "cd replan "+app, "replan-app"); done {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			row, err := cdApp(c, g, s, tenant, app)
			if err != nil {
				return err
			}
			target, expected, err := cdTarget(row.CD, &revision)
			if err != nil {
				return err
			}
			return g.sendAndPrint(c, s, fmt.Sprintf("Plan the candidate of app %s again.", app), change{ID: id.Get(), Summary: "cd replan " + app, Action: "replan-app", Expected: expected, Payload: control.AppCDChange{Tenant: tenant, App: app, Target: target}})
		}),
	}
}
