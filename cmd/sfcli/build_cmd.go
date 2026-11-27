// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/imagecache"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/userauth"
)

// sfcli build: image builds. A context is where the build files come from
// (an uploaded ZIP, a Git repository or a draft edited here); each saved set
// of files is a numbered version; a build runs one version.

func buildCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "build",
		Short: "Image builds: contexts, drafts, runs, logs, cache and policy",
		Sub: []*cli.Command{
			buildContextCommand(g),
			buildDraftCommand(g),
			buildRunCommand(g),
			buildListCommand(g),
			{Name: "show", Args: "BUILD", Short: "Show one build", Run: g.withSession(buildShow(g))},
			buildLogsCommand(g),
			buildJobChangeCommand(g, "cancel", "cancel-image-build", "Cancel a queued or running build"),
			buildJobChangeCommand(g, "delete", "delete-image-build-job", "Delete a finished build's record"),
			buildCacheCommand(g),
			buildPolicyCommand(g),
		},
	}
}

func init() {
	opKinds["build-run"] = buildRunHandler
	opKinds["build-cache-prune"] = buildCachePruneHandler
}

// buildPart reads every page of one part of the build state.
func buildPart(ctx context.Context, s *session, tenant string, q control.ImageBuildQuery) (control.ImageBuildPage, error) {
	var out control.ImageBuildPage
	after := ""
	for i := 0; ; i++ {
		p, err := s.Client.ImageBuilds(ctx, s.Target, s.Stored.Session, tenant, q, after)
		if err != nil {
			return out, err
		}
		if i == 0 {
			out = p
		} else {
			if p.RootRevision != out.RootRevision {
				return out, errors.New("builds changed while reading; run the command again")
			}
			out.Policies = append(out.Policies, p.Policies...)
			out.Contexts = append(out.Contexts, p.Contexts...)
			out.Uploads = append(out.Uploads, p.Uploads...)
			out.Versions = append(out.Versions, p.Versions...)
			out.Jobs = append(out.Jobs, p.Jobs...)
			out.Caches = append(out.Caches, p.Caches...)
			out.CachePrunes = append(out.CachePrunes, p.CachePrunes...)
		}
		if p.Next == "" {
			out.Next = ""
			return out, nil
		}
		if p.Next == after || i > 4096 {
			return out, errors.New("the server sent an invalid build page cursor")
		}
		after = p.Next
	}
}

func findJob(ctx context.Context, s *session, tenant, id string) (control.ImageBuildJobView, uint64, error) {
	p, err := s.Client.ImageBuilds(ctx, s.Target, s.Stored.Session, tenant, control.ImageBuildQuery{Part: "jobs", Job: id}, "")
	if err != nil {
		return control.ImageBuildJobView{}, 0, err
	}
	for _, j := range p.Jobs {
		if j.ID == id && !j.Deleted {
			return j, p.Epoch, nil
		}
	}
	return control.ImageBuildJobView{}, 0, fmt.Errorf("no build %q in tenant %s", id, tenant)
}

func unixTime(at uint64) string {
	if at == 0 {
		return ""
	}
	return time.Unix(int64(at), 0).Local().Format("2006-01-02 15:04")
}

func buildJobState(j control.ImageBuildJobView) (cli.State, string) {
	line := j.Phase
	if j.Cancel && !slices.Contains([]string{"succeeded", "failed", "cancelled"}, j.Phase) {
		line += " (cancelling)"
	}
	if j.Result != nil {
		if j.Result.Code == "OK" {
			line += ": " + j.Result.Image
		} else {
			line += ": " + j.Result.Code
			if j.Result.Code == "BUILD_FAILED" {
				line += "; the failed step and its output are in 'sfcli build logs " + j.ID + "'"
			}
		}
	}
	switch j.Phase {
	case "succeeded", "cancelled":
		return cli.Done, line
	case "failed":
		return cli.Failed, line
	}
	return cli.Accepted, line
}

func jobRows(jobs []control.ImageBuildJobView) func() cli.Rows {
	return func() cli.Rows {
		t := cli.Rows{Header: []string{"build", "context", "version", "node", "state", "created"}}
		for _, j := range jobs {
			_, line := buildJobState(j)
			t.Add(j.ID, j.Context, j.Number, j.Node, line, unixTime(j.CreatedAt))
		}
		return t
	}
}

func buildListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Args:  "[CONTEXT]",
		Short: "List builds, newest first",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) > 1 || len(args) == 1 && !lifecycle.ValidID(args[0]) {
				return cli.Usagef("takes at most one context name")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			q := control.ImageBuildQuery{Part: "jobs"}
			if len(args) == 1 {
				q.ID = args[0]
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			p, err := buildPart(ctx, s, tenant, q)
			if err != nil {
				return err
			}
			jobs := slices.DeleteFunc(p.Jobs, func(j control.ImageBuildJobView) bool { return j.Deleted })
			slices.SortStableFunc(jobs, func(a, b control.ImageBuildJobView) int { return int(int64(b.CreatedAt) - int64(a.CreatedAt)) })
			if jobs == nil {
				jobs = []control.ImageBuildJobView{}
			}
			return cli.Print(c.Out, g.output.Format(), jobs, jobRows(jobs))
		}),
	}
}

func buildShow(g *globals) func(*cli.Context, *session, []string) error {
	return func(c *cli.Context, s *session, args []string) error {
		id, err := oneName(args, "build name")
		if err != nil {
			return err
		}
		tenant, err := g.Tenant(s, true)
		if err != nil {
			return err
		}
		ctx, cancel := g.Deadline(c)
		defer cancel()
		j, _, err := findJob(ctx, s, tenant, id)
		if err != nil {
			return err
		}
		_, line := buildJobState(j)
		return cli.Print(c.Out, g.output.Format(), struct {
			State string `json:"state"`
			control.ImageBuildJobView
		}{line, j}, nil)
	}
}

// liveVersions returns the kept versions of a context, newest first.
func liveVersions(ctx context.Context, s *session, tenant, id string) ([]control.ImageBuildVersionView, error) {
	p, err := buildPart(ctx, s, tenant, control.ImageBuildQuery{Part: "versions", ID: id})
	if err != nil {
		return nil, err
	}
	out := slices.DeleteFunc(p.Versions, func(v control.ImageBuildVersionView) bool { return v.Deleted || v.Context != id })
	slices.SortFunc(out, func(a, b control.ImageBuildVersionView) int { return int(int64(b.Number) - int64(a.Number)) })
	return out, nil
}

// pickVersion returns version n of a context, or the newest when n is "".
func pickVersion(ctx context.Context, s *session, tenant, id, n string) (control.ImageBuildVersionView, error) {
	vs, err := liveVersions(ctx, s, tenant, id)
	if err != nil {
		return control.ImageBuildVersionView{}, err
	}
	if len(vs) == 0 {
		return control.ImageBuildVersionView{}, fmt.Errorf("context %s has no version yet; upload or freeze one first", id)
	}
	if n == "" {
		return vs[0], nil
	}
	number, err := strconv.ParseUint(n, 10, 64)
	if err != nil {
		return control.ImageBuildVersionView{}, cli.Usagef("version %q must be a number", n)
	}
	for _, v := range vs {
		if v.Number == number {
			return v, nil
		}
	}
	return control.ImageBuildVersionView{}, fmt.Errorf("context %s has no kept version %d", id, number)
}

// buildApprovals asks for the Group passwords of the secrets a build
// mounts, as an app deployment does.
func buildApprovals(c *cli.Context, g *globals, s *session, origin control.UserOperation, resume bool, passwords groupPasswordFDs) error {
	tenant, err := g.Tenant(s, true)
	if err != nil {
		return err
	}
	ctx, cancel := g.Deadline(c)
	defer cancel()
	known, err := s.Client.Result(ctx, s.Target, s.Stored.Session, origin)
	if err != nil {
		return err
	}
	if known.Found && known.Result != nil {
		return nil // already settled: nothing to approve
	}
	var start control.ImageBuildJobStart
	if err = json.Unmarshal(origin.Change.Payload, &start); err != nil {
		return err
	}
	p, err := s.Client.ImageBuilds(ctx, s.Target, s.Stored.Session, tenant, control.ImageBuildQuery{Part: "contexts", ID: start.Context}, "")
	if err != nil {
		return err
	}
	if len(p.Contexts) != 1 || p.Contexts[0].Deleted {
		return errors.New("the build context changed; run 'sfcli build run' again")
	}
	var realms []string
	for _, ref := range p.Contexts[0].Spec.Secrets {
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

func buildProgress(c *cli.Context, g *globals, s *session, tenant, id string) (cli.State, string, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	j, _, err := findJob(ctx, s, tenant, id)
	if err != nil {
		return "", "", err
	}
	st, line := buildJobState(j)
	return st, line, nil
}

func buildRunHandler(g *globals) cli.Handler {
	base := changeHandler(g, func(c *cli.Context, s *session, op control.UserOperation) error {
		return buildApprovals(c, g, s, op, true, groupPasswordFDs{})
	}, true)
	then := func(call func(*cli.Context, cli.Op) (cli.State, string, error)) func(*cli.Context, cli.Op) (cli.State, string, error) {
		return func(c *cli.Context, op cli.Op) (cli.State, string, error) {
			st, line, err := call(c, op)
			if err != nil || st != cli.Accepted {
				return st, line, err
			}
			s, err := g.opSession(c, op)
			if err != nil {
				return "", "", err
			}
			defer s.Close()
			return buildProgress(c, g, s, op.Tenant, op.ID)
		}
	}
	return cli.Handler{Show: then(base.Show), Resume: then(base.Resume)}
}

func buildRunCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var wait waitFlags
	var logs bool
	var passwords groupPasswordFDs
	return &cli.Command{
		Name:  "run",
		Args:  "CONTEXT [VERSION]",
		Short: "Build an image from a context version (default the newest)",
		Long: `Starts a build of one version of the context and waits until it ends.
The build's name is its operation ID. --logs prints the build output while
waiting. If the context mounts protected Vault secrets, their Group
passwords are asked for on the terminal, or read from --group-password-fd in
scripts.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "build name and operation `id` (default: a new one)")
			fs.Var(&passwords, "group-password-fd", "for scripts: read the password of `REALM/GROUP=FD` (cluster: /GROUP) from that open file descriptor (repeat)")
			fs.BoolVar(&logs, "logs", false, "print the build output while waiting")
			wait.register(fs)
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) < 1 || len(args) > 2 || !lifecycle.ValidID(args[0]) {
				return cli.Usagef("needs CONTEXT and optionally VERSION")
			}
			number := ""
			if len(args) == 2 {
				number = args[1]
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			v, err := pickVersion(ctx, s, tenant, args[0], number)
			if err != nil {
				return err
			}
			job := id.Get()
			plan, err := s.Client.PlanImageBuildJob(ctx, s.Target, s.Stored.Session, tenant, control.ImageBuildJobQuery{ID: job, Context: args[0], Version: v.ID})
			if remote := (*userauth.Error)(nil); errors.As(err, &remote) && remote.Code == "build-disabled" {
				return fmt.Errorf("the context's server does not build (its engine has builds off, or its workload module is off); 'sfcli node list' shows each server's build column: %w", err)
			}
			if err != nil {
				return err
			}
			ch := change{Kind: "build-run", Summary: fmt.Sprintf("build run %s %d", args[0], v.Number), ID: job, Action: "begin-image-build", Epoch: plan.Epoch, Payload: plan.Change, Async: true}
			ch.Before = func(origin control.UserOperation) error { return buildApprovals(c, g, s, origin, false, passwords) }
			if _, err = g.send(c, s, ch); err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "build %s: %s version %d\n", job, args[0], v.Number)
			if wait.noWait {
				fmt.Fprintf(c.Out, "accepted %s; follow it with 'sfcli build logs %s -f'\n", job, job)
				return nil
			}
			if logs {
				if err = followLogs(c, g, s, tenant, job, false); err != nil {
					return err
				}
			}
			_, line, err := g.follow(c, job, func(c *cli.Context) (cli.State, string, error) {
				return buildProgress(c, g, s, tenant, job)
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "build %s %s\n", job, line)
			return nil
		}),
	}
}

// followLogs prints a build's output; with tail only the last page, and it
// keeps reading until the build ends.
func followLogs(c *cli.Context, g *globals, s *session, tenant, job string, tail bool) error {
	after := ""
	for {
		ctx, cancel := g.Deadline(c)
		page, err := s.Client.ImageBuildLogs(ctx, s.Target, s.Stored.Session, tenant, imagebuild.LogQuery{Job: job, MaxBytes: imagebuild.MaxLogPageBytes, Tail: tail && after == ""}, after)
		cancel()
		if err != nil {
			if c.Ctx.Err() != nil {
				return nil
			}
			return err
		}
		if page.Page.Gap {
			fmt.Fprintln(c.Err, "[some output was not kept]")
		}
		if _, err = c.Out.Write(page.Page.Data); err != nil {
			return err
		}
		if page.Next != "" && page.Next != after {
			after = page.Next
			continue
		}
		if page.Page.Truncated {
			fmt.Fprintln(c.Err, "[the rest of the output was not kept]")
		}
		if slices.Contains([]string{"succeeded", "failed", "cancelled"}, page.Phase) && !page.Page.Unclosed {
			return nil
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-c.Ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func buildLogsCommand(g *globals) *cli.Command {
	var follow, tail bool
	return &cli.Command{
		Name:  "logs",
		Args:  "BUILD",
		Short: "Print a build's output",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&follow, "f", false, "keep printing until the build ends")
			fs.BoolVar(&tail, "tail", false, "start from the last page")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			id, err := oneName(args, "build name")
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			if follow {
				return followLogs(c, g, s, tenant, id, tail)
			}
			after := ""
			for {
				ctx, cancel := g.Deadline(c)
				page, err := s.Client.ImageBuildLogs(ctx, s.Target, s.Stored.Session, tenant, imagebuild.LogQuery{Job: id, MaxBytes: imagebuild.MaxLogPageBytes, Tail: tail && after == ""}, after)
				cancel()
				if err != nil {
					return err
				}
				if _, err = c.Out.Write(page.Page.Data); err != nil {
					return err
				}
				if page.Next == "" || page.Next == after || page.Page.Next >= page.Page.Total {
					return nil
				}
				after = page.Next
			}
		}),
	}
}

func buildJobChangeCommand(g *globals, verb, action, short string) *cli.Command {
	var id cli.IDFlag
	var rev cli.RevisionFlag
	return &cli.Command{
		Name:  verb,
		Args:  "BUILD",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.Var(&rev, "if-revision", "only if the build is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			job, err := oneName(args, "build name")
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			j, epoch, err := findJob(ctx, s, tenant, job)
			if err != nil {
				return err
			}
			expected, err := rev.Resolve(func() (uint64, error) { return j.Revision, nil })
			if err != nil {
				return err
			}
			_, line := buildJobState(j)
			fmt.Fprintf(c.Err, "%s build %s (%s version %d, %s).\n", short, job, j.Context, j.Number, line)
			if err = g.Prompter(c).Confirm("Go ahead?"); err != nil {
				return err
			}
			opID := id.Get()
			if _, err = g.send(c, s, change{Summary: "build " + verb + " " + job, ID: opID, Action: action, Expected: expected, Epoch: epoch, Payload: control.ImageBuildJobSelection{Tenant: tenant, ID: job}}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "build %s: %s accepted (%s)\n", job, verb, opID)
			return nil
		}),
	}
}

// --- cache ---

func buildCacheCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "cache",
		Short: "Build cache on the build servers",
		Sub: []*cli.Command{
			buildCacheListCommand(g),
			buildCacheShowCommand(g),
			buildCachePruneCommand(g),
		},
	}
}

func parseCacheID(s string) ([32]byte, error) {
	var cache [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != s || s == strings.Repeat("0", 64) {
		return cache, cli.Usagef("cache ID must be 64 lower-case hex characters (see 'sfcli build cache list')")
	}
	copy(cache[:], raw)
	return cache, nil
}

func cacheSize(r control.ImageBuildCacheInventoryRow) string {
	if r.Usage == nil {
		return ""
	}
	return cli.Size(max(r.Usage.ReportedBytes, 0)).String()
}

func readCaches(ctx context.Context, s *session, tenant, context, node string) ([]control.ImageBuildCacheInventoryRow, uint64, error) {
	p, err := buildPart(ctx, s, tenant, control.ImageBuildQuery{Part: "caches", ID: context, Node: node})
	if err != nil {
		return nil, 0, err
	}
	if p.Caches == nil {
		p.Caches = []control.ImageBuildCacheInventoryRow{}
	}
	return p.Caches, p.Epoch, nil
}

func buildCacheListCommand(g *globals) *cli.Command {
	var node string
	return &cli.Command{
		Name:  "list",
		Args:  "[CONTEXT]",
		Short: "List build caches per server and context",
		Flags: func(fs *flag.FlagSet) { fs.StringVar(&node, "node", "", "only this server") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			cx := ""
			if len(args) == 1 {
				cx = args[0]
			} else if len(args) > 1 {
				return cli.Usagef("takes at most one context name")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			rows, _, err := readCaches(ctx, s, tenant, cx, node)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"cache", "node", "context", "size", "state"}}
				for _, r := range rows {
					t.Add(hex.EncodeToString(r.Cache[:]), r.Node, r.Context, cacheSize(r), r.Code)
				}
				return t
			})
		}),
	}
}

func buildCacheShowCommand(g *globals) *cli.Command {
	var node string
	return &cli.Command{
		Name:  "show",
		Args:  "CACHE --node NODE",
		Short: "Show the entries of one build cache",
		Flags: func(fs *flag.FlagSet) { fs.StringVar(&node, "node", "", "server of the cache (required)") },
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 || node == "" {
				return cli.Usagef("needs CACHE and --node")
			}
			cache, err := parseCacheID(args[0])
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			var entries []imagebuild.CacheEntry
			var first control.ImageBuildCachePage
			after := ""
			for i := 0; ; i++ {
				ctx, cancel := g.Deadline(c)
				page, err := s.Client.ImageBuildCacheUsage(ctx, s.Target, s.Stored.Session, tenant, imagebuild.CacheQuery{Cache: &cache, Node: node}, after)
				cancel()
				if err != nil {
					return err
				}
				if i == 0 {
					first = page
				}
				entries = append(entries, page.Page.Entries...)
				if page.Next == "" || page.Next == after || i > 4096 {
					break
				}
				after = page.Next
			}
			first.Page.Entries, first.Next = entries, ""
			return cli.Print(c.Out, g.output.Format(), first, func() cli.Rows {
				t := cli.Rows{Header: []string{"entry", "kind", "size", "last used", "in use"}}
				for _, e := range entries {
					t.Add(e.ID, e.Kind, cli.Size(max(e.Bytes, 0)), unixTime(uint64(max(e.LastUsedAt, 0))), e.InUse)
				}
				return t
			})
		}),
	}
}

func cachePruneState(v control.ImageBuildCachePruneView) (cli.State, string) {
	line := v.State
	if v.Code != "" {
		line += " (" + v.Code + ")"
	}
	if v.ReportedBytes > 0 {
		line += ", freed " + cli.Size(v.ReportedBytes).String()
	}
	switch v.State {
	case "done", "finished", "succeeded":
		if v.Code == "" || v.Code == "OK" {
			return cli.Done, line
		}
		return cli.Failed, line
	case "failed":
		return cli.Failed, line
	}
	if v.ClosedAt != 0 {
		if v.Code == "" || v.Code == "OK" {
			return cli.Done, line
		}
		return cli.Failed, line
	}
	return cli.Accepted, line
}

func cachePruneProgress(c *cli.Context, g *globals, s *session, tenant, id string) (cli.State, string, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	p, err := buildPart(ctx, s, tenant, control.ImageBuildQuery{Part: "cache-prunes", ID: id})
	if err != nil {
		return "", "", err
	}
	for _, v := range p.CachePrunes {
		if v.ID == id {
			st, line := cachePruneState(v)
			return st, line, nil
		}
	}
	return cli.Accepted, "queued", nil
}

func buildCachePruneHandler(g *globals) cli.Handler {
	base := changeHandler(g, nil, true)
	then := func(call func(*cli.Context, cli.Op) (cli.State, string, error)) func(*cli.Context, cli.Op) (cli.State, string, error) {
		return func(c *cli.Context, op cli.Op) (cli.State, string, error) {
			st, line, err := call(c, op)
			if err != nil || st != cli.Accepted {
				return st, line, err
			}
			s, err := g.opSession(c, op)
			if err != nil {
				return "", "", err
			}
			defer s.Close()
			return cachePruneProgress(c, g, s, op.Tenant, op.ID)
		}
	}
	return cli.Handler{Show: then(base.Show), Resume: then(base.Resume)}
}

func buildCachePruneCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var wait waitFlags
	var node, cacheID string
	var unusedDays uint
	var entries listFlag
	return &cli.Command{
		Name:  "prune",
		Args:  "[CONTEXT]",
		Short: "Clear build caches",
		Long: `Clears every build cache of the tenant, of one CONTEXT, of one --node or
one --cache. --unused-days keeps entries used more recently; --entry clears
only the named entries of one --cache.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one; several caches get -1, -2, ...)")
			fs.StringVar(&node, "node", "", "only caches on this server")
			fs.StringVar(&cacheID, "cache", "", "only this cache (needs --node)")
			fs.UintVar(&unusedDays, "unused-days", 0, "only entries unused for this many days")
			fs.Var(&entries, "entry", "only this entry `ID` of --cache (repeatable)")
			wait.register(fs)
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			cx := ""
			if len(args) == 1 {
				cx = args[0]
			} else if len(args) > 1 {
				return cli.Usagef("takes at most one context name")
			}
			filter := imagebuild.CachePruneFilter{Mode: "all"}
			switch {
			case len(entries) > 0 && unusedDays > 0:
				return cli.Usagef("--entry and --unused-days cannot be combined")
			case len(entries) > 0:
				if cacheID == "" {
					return cli.Usagef("--entry needs --cache")
				}
				filter = imagebuild.CachePruneFilter{Mode: "entries", IDs: slices.Sorted(slices.Values(entries))}
			case unusedDays > 0:
				filter = imagebuild.CachePruneFilter{Mode: "unused", UnusedDays: uint32(min(unusedDays, 1<<31))}
			}
			if !filter.Valid() {
				return cli.Usagef("invalid entry IDs")
			}
			if cacheID != "" && node == "" {
				return cli.Usagef("--cache needs --node")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			rows, epoch, err := readCaches(ctx, s, tenant, cx, node)
			if err != nil {
				return err
			}
			if cacheID != "" {
				cache, err := parseCacheID(cacheID)
				if err != nil {
					return err
				}
				rows = slices.DeleteFunc(rows, func(r control.ImageBuildCacheInventoryRow) bool { return r.Cache != cache })
			}
			if len(rows) == 0 {
				fmt.Fprintln(c.Out, "no build cache matches")
				return nil
			}
			fmt.Fprintf(c.Err, "Clear %d build caches (%s):\n", len(rows), filter.Mode)
			for _, r := range rows {
				fmt.Fprintf(c.Err, "  %s  %s  %s  %s\n", r.Node, r.Context, hex.EncodeToString(r.Cache[:8]), cacheSize(r))
			}
			if err = g.Prompter(c).Confirm("Clear them?"); err != nil {
				return err
			}
			base := id.Get()
			var ids []string
			for i, r := range rows {
				opID := base
				if len(rows) > 1 {
					opID = fmt.Sprintf("%s-%d", base[:min(len(base), 56)], i+1)
				}
				q := control.ImageBuildCachePruneChange{Tenant: tenant, ID: opID, Node: r.Node, Cache: r.Cache, Filter: filter.Own()}
				if !q.Valid() {
					return errors.New("invalid cache cleanup")
				}
				summary := fmt.Sprintf("build cache prune %s --node %s --cache %s", r.Context, r.Node, hex.EncodeToString(r.Cache[:]))
				if _, err = g.send(c, s, change{Kind: "build-cache-prune", Summary: summary, ID: opID, Action: control.ImageBuildCachePruneAction, Epoch: epoch, Payload: q, Async: true}); err != nil {
					return err
				}
				ids = append(ids, opID)
			}
			if wait.noWait {
				fmt.Fprintf(c.Out, "accepted %s; check with 'sfcli op show ID'\n", strings.Join(ids, ", "))
				return nil
			}
			var failed error
			for _, opID := range ids {
				_, line, err := g.follow(c, opID, func(c *cli.Context) (cli.State, string, error) {
					return cachePruneProgress(c, g, s, tenant, opID)
				})
				var running errStillRunning
				if errors.As(err, &running) {
					return err
				}
				if err != nil {
					failed = err
					continue
				}
				fmt.Fprintf(c.Out, "%s: %s\n", opID, line)
			}
			return failed
		}),
	}
}

// --- policy ---

// buildPolicyFile is build-policy.yaml (sfcli build policy set -f).
type buildPolicyFile struct {
	Version      int               `yaml:"version"`
	Nodes        map[string]string `yaml:"nodes"` // server: storage root ID
	Concurrency  uint32            `yaml:"concurrency"`
	Timeout      string            `yaml:"timeout"`
	CPU          float64           `yaml:"cpu"`
	Memory       string            `yaml:"memory"`
	Workspace    string            `yaml:"workspace"`
	Cache        string            `yaml:"cache"`
	Registry     string            `yaml:"registry"`
	Platforms    []string          `yaml:"platforms"`
	BuilderImage string            `yaml:"builder_image"`
	Cleanup      struct {
		HighWaterPercent uint8  `yaml:"high_water_percent"`
		UnusedDays       uint32 `yaml:"unused_days"`
	} `yaml:"cleanup"`
}

func currentPolicy(ctx context.Context, s *session, tenant string) (*control.ImageBuildPolicyView, error) {
	p, err := buildPart(ctx, s, tenant, control.ImageBuildQuery{Part: "policy"})
	if err != nil {
		return nil, err
	}
	for i := range p.Policies {
		if p.Policies[i].Spec.Tenant == tenant && !p.Policies[i].Deleted {
			return &p.Policies[i], nil
		}
	}
	return nil, nil
}

func policyFileOf(p imagebuild.Policy) buildPolicyFile {
	f := buildPolicyFile{Version: 1, Nodes: map[string]string{}, Concurrency: p.Concurrency, Timeout: (time.Duration(p.Seconds) * time.Second).String(),
		CPU: float64(p.CPUMillis) / 1000, Memory: cli.Size(max(p.MemoryBytes, 0)).String(), Workspace: cli.Size(max(p.WorkspaceBytes, 0)).String(),
		Cache: cli.Size(max(p.CacheBytes, 0)).String(), Registry: p.Registry, Platforms: p.Platforms, BuilderImage: p.BuilderImage}
	for _, n := range p.Nodes {
		f.Nodes[n.Node] = n.Root.ID
	}
	f.Cleanup.HighWaterPercent, f.Cleanup.UnusedDays = p.Cleanup.HighWaterPercent, p.Cleanup.UnusedDays
	return f
}

func buildPolicyCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "policy",
		Short: "Where and with how much the tenant's builds run",
		Sub: []*cli.Command{
			{
				Name:  "show",
				Short: "Show the build policy (as build-policy.yaml with -o yaml)",
				Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
					if len(args) != 0 {
						return cli.Usagef("show takes no arguments")
					}
					tenant, err := g.Tenant(s, true)
					if err != nil {
						return err
					}
					ctx, cancel := g.Deadline(c)
					defer cancel()
					cur, err := currentPolicy(ctx, s, tenant)
					if err != nil {
						return err
					}
					if cur == nil {
						return fmt.Errorf("tenant %s has no build policy; set one with 'sfcli build policy set -f build-policy.yaml'", tenant)
					}
					if g.output.Format() == cli.YAML {
						return yaml.NewEncoder(c.Out).Encode(policyFileOf(cur.Spec))
					}
					return cli.Print(c.Out, g.output.Format(), cur, nil)
				}),
			},
			buildPolicySetCommand(g),
		},
	}
}

func readYAMLFile(path string, limit int64, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return fmt.Errorf("%s must be a regular file of at most %s", path, cli.Size(limit))
	}
	d := yaml.NewDecoder(f)
	d.KnownFields(true)
	if err = d.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func buildPolicySetCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var rev cli.RevisionFlag
	var file string
	return &cli.Command{
		Name:  "set",
		Args:  "-f build-policy.yaml",
		Short: "Set the build policy from a file",
		Long: `Sets the tenant's build policy. The file (see docs/cli/build.md):

  version: 1
  nodes: {node-a: data}       # server: storage root
  concurrency: 2
  timeout: 30m
  cpu: 2
  memory: 4GiB
  workspace: 10GiB
  cache: 20GiB
  registry: shop-registry
  platforms: [linux/amd64]
  builder_image: registry.example/moby/buildkit:v0.35
  cleanup: {high_water_percent: 80, unused_days: 14}`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.Var(&rev, "if-revision", "only if the policy is still at this `revision`")
			fs.StringVar(&file, "f", "", "build-policy.yaml (required)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 || file == "" {
				return cli.Usagef("needs -f build-policy.yaml")
			}
			var f buildPolicyFile
			if err := readYAMLFile(file, 64<<10, &f); err != nil {
				return err
			}
			if f.Version != 1 {
				return cli.Usagef("%s: version must be 1", file)
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			timeout, err := time.ParseDuration(f.Timeout)
			if err != nil || timeout < time.Second {
				return cli.Usagef("%s: timeout must look like 30m", file)
			}
			sizes := map[string]*int64{}
			var memory, workspace, cache int64
			sizes["memory"], sizes["workspace"], sizes["cache"] = &memory, &workspace, &cache
			for key, text := range map[string]string{"memory": f.Memory, "workspace": f.Workspace, "cache": f.Cache} {
				v, err := cli.ParseSize(text)
				if err != nil || v == 0 || v > 1<<62 {
					return cli.Usagef("%s: %s must be a size such as 4GiB", file, key)
				}
				*sizes[key] = int64(v)
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			cur, err := currentPolicy(ctx, s, tenant)
			if err != nil {
				return err
			}
			spec := imagebuild.Policy{Schema: 1, Tenant: tenant, Concurrency: f.Concurrency, Seconds: uint64(timeout / time.Second), CPUMillis: uint64(f.CPU * 1000),
				MemoryBytes: memory, WorkspaceBytes: workspace, CacheBytes: cache, Registry: f.Registry, Platforms: f.Platforms,
				Cleanup: imagebuild.CleanupPolicy{HighWaterPercent: f.Cleanup.HighWaterPercent, UnusedDays: f.Cleanup.UnusedDays}}
			for _, node := range slices.Sorted(mapKeys(f.Nodes)) {
				ref, err := storageRoot(ctx, s, tenant, cur, node, f.Nodes[node])
				if err != nil {
					return err
				}
				spec.Nodes = append(spec.Nodes, imagebuild.NodeRoot{Node: node, Root: ref})
			}
			spec.BuilderImage = f.BuilderImage
			if f.BuilderImage != "" && !strings.Contains(f.BuilderImage, "@sha256:") {
				res, err := s.Client.ResolveImage(ctx, s.Target, s.Stored.Session, tenant, control.ImageResolveQuery{Ref: f.BuilderImage})
				if err != nil {
					return fmt.Errorf("%s: cannot pin builder_image %s to a digest: %w", file, f.BuilderImage, err)
				}
				if res.Code != "OK" || res.Image == nil {
					hint := "give name@sha256:..."
					if res.Code == "UNTRUSTED" {
						hint = "trust its registry first with 'sfcli tenant trust add'"
					}
					return fmt.Errorf("%s: cannot pin builder_image %s to a digest (%s); %s", file, f.BuilderImage, res.Code, hint)
				}
				spec.BuilderImage = res.Image.Pinned
			}
			if spec.Validate(s.Client.Cluster) != nil {
				return cli.Usagef("%s: invalid policy: at least one server, concurrency 1..32, timeout up to 24h, cpu and sizes above 0, cleanup high_water_percent 1..100 and unused_days above 0, a registry, platforms and a builder_image", file)
			}
			// The server never pulls the builder image; say now which build
			// servers lack it instead of failing every build there later.
			missing, checked := builderImageMissing(ctx, s, spec)
			if len(missing) > 0 {
				return fmt.Errorf("%s: builder_image %s is not on %s; pull it on each of those servers first (the server does not pull it)", file, spec.BuilderImage, strings.Join(missing, ", "))
			}
			if !checked {
				fmt.Fprintf(c.Err, "Could not check that every build server has %s (listing server images needs a system administrator); each server must have it pulled.\n", spec.BuilderImage)
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
				fmt.Fprintf(c.Err, "Replace the build policy of %s (revision %d).\n", tenant, cur.Revision)
				if err = g.Prompter(c).Confirm("Replace it?"); err != nil {
					return err
				}
			}
			opID := id.Get()
			if _, err = g.send(c, s, change{Summary: "build policy set " + tenant, ID: opID, Action: "set-image-build-policy", Expected: expected, Payload: control.ImageBuildPolicyPut{Spec: spec}}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "build policy of %s set (%s)\n", tenant, opID)
			return nil
		}),
	}
}

func mapKeys(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// builderImageMissing lists the policy servers whose Docker cache lacks the
// pinned builder image. checked is false when a server's images could not
// be listed (the listing is a system administrator read).
func builderImageMissing(ctx context.Context, s *session, spec imagebuild.Policy) (missing []string, checked bool) {
	want, err := imagecache.CanonicalReference(spec.BuilderImage)
	if err != nil {
		return nil, false
	}
	for _, n := range spec.Nodes {
		found, ok := nodeHasImage(ctx, s, n.Node, want)
		if !ok {
			return nil, false
		}
		if !found {
			missing = append(missing, n.Node)
		}
	}
	return missing, true
}

func nodeHasImage(ctx context.Context, s *session, node, want string) (found, ok bool) {
	q := imagecache.Query{Node: node}
	for range 256 {
		reply, err := s.Client.QueryImageCache(ctx, s.Target, s.Stored.Session, true, q)
		if err != nil || reply.ImageCachePlan == nil {
			return false, false
		}
		for _, image := range reply.ImageCachePlan.Images {
			if slices.Contains(image.Aliases, want) {
				return true, true
			}
		}
		if q.After = reply.ImageCachePlan.Next; q.After == "" {
			return false, true
		}
	}
	return false, false
}

// storageRoot finds the storage root reference for a policy server: the
// current policy's when it is the same root, else the tenant storage row.
func storageRoot(ctx context.Context, s *session, tenant string, cur *control.ImageBuildPolicyView, node, id string) (nodestorage.Reference, error) {
	if cur != nil {
		for _, n := range cur.Spec.Nodes {
			if n.Node == node && n.Root.ID == id {
				return n.Root, nil
			}
		}
	}
	after := ""
	for range 4096 {
		p, err := s.Client.TenantStoragePage(ctx, s.Target, s.Stored.Session, tenant, node, after)
		if err != nil {
			return nodestorage.Reference{}, err
		}
		for _, x := range p.TenantStorage {
			if x.Node == node && x.ID == id && x.Allowed && !x.Draining && x.Root.ID != "" {
				return x.Root, nil
			}
		}
		if p.TenantStorageNext == "" || p.TenantStorageNext == after {
			break
		}
		after = p.TenantStorageNext
	}
	return nodestorage.Reference{}, fmt.Errorf("server %s has no storage root %q this tenant may use (see 'sfcli node storage')", node, id)
}
