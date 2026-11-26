// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

type composeOptions struct {
	standalone                                      *control.StandaloneDefinition
	container                                       *containerCLIOptions
	method                                          string
	file, project, tenant, deployment, node, output onceString
	plan, operation                                 onceString
	condition                                       onceString
	sourceOperation                                 onceString
	retrySource                                     checkerRetryFlag
	logClearPreview, logClearRecreate               checkerRetryFlag
	passwordFDs                                     groupPasswordFDs
	noInput                                         bool
}

func parseComposeOptions(args []string, diagnostic io.Writer) (composeOptions, error) {
	return parseComposeDefaults(args, diagnostic, cliprofile.Selection{})
}

func parseComposeDefaults(args []string, diagnostic io.Writer, defaults cliprofile.Selection) (composeOptions, error) {
	args = expandContainerExecFlags(args)
	var o composeOptions
	o.project.value, o.node.value = defaults.Project, defaults.Node
	f := flag.NewFlagSet("compose", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	o.container = addContainerReadFlags(f)
	f.Var(&o.logClearPreview, "preview", "show exact restart or log-clear plan without mutation")
	f.Var(&o.logClearRecreate, "recreate", "explicitly consent to container recreation and irreversible local log/writable-layer loss")
	f.Var(&o.file, "f", "single app.yaml specification")
	f.Var(&o.file, "file", "single app.yaml specification")
	f.Var(&o.project, "p", "project name")
	f.Var(&o.project, "project-name", "project name")
	f.Var(&o.tenant, "tenant", "tenant (default selected tenant)")
	f.Var(&o.deployment, "deployment-id", "stable deployment identity")
	f.Var(&o.node, "node", "default admitted node")
	f.Var(&o.output, "out", "atomically save a private plan artifact")
	f.Var(&o.plan, "plan", "frozen Blueprint artifact for up")
	f.Var(&o.operation, "operation", "stable original deployment operation ID")
	f.Var(&o.condition, "condition", "wait for healthy (default) or retired")
	f.Var(&o.sourceOperation, "source-operation", "read original compose source preparation for plan/diff")
	f.Var(&o.retrySource, "retry-source", "explicitly resend original source only after confirmed missing (resume)")
	f.Var(&o.passwordFDs, "group-password-fd", "explicit REALM/GROUP=FD (cluster: /GROUP), repeat per required group")
	f.BoolVar(&o.noInput, "no-input", false, "use existing approvals/explicit FDs without a terminal prompt")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	rest := f.Args()
	if len(rest) == 0 {
		return o, errors.New("compose requires config, plan, diff, up, resume, down, ps, status, wait, logs, top, stats, logs-clear or logs-clear-status")
	}
	o.method = rest[0]
	if err := f.Parse(rest[1:]); err != nil {
		return o, errors.New("invalid compose options")
	}
	if containerReadMethod(o.method) || o.method == "restart" || o.method == "logs-clear" || o.method == "exec" {
		trailing := f.Args()
		if len(trailing) == 0 {
			return o, errors.New("container query requires a service")
		}
		o.container.service = trailing[0]
		if o.method == "exec" {
			if !slices.Contains(trailing[1:], "--") {
				return o, errors.New("exec requires SERVICE -- ARG [ARG ...]")
			}
			if err := f.Parse(trailing[1:]); err != nil {
				return o, err
			}
			o.container.argv = slices.Clone(f.Args())
		} else if err := f.Parse(trailing[1:]); err != nil || f.NArg() != 0 {
			return o, errors.New("container query requires exactly one service")
		}
	} else if f.NArg() != 0 {
		return o, errors.New("invalid compose options")
	}
	invalidReadFlag := false
	if !containerReadMethod(o.method) {
		f.Visit(func(v *flag.Flag) {
			invalidReadFlag = invalidReadFlag || containerReadFlag(v.Name) && !((o.method == "restart" || o.method == "logs-clear") && v.Name == "instance") && !(o.method == "exec" && containerExecFlag(v.Name)) && !(o.method == "exec-status" && v.Name == "json")
		})
	}
	if invalidReadFlag {
		return o, errors.New("container observation options require logs, top or stats")
	}
	if o.method != "restart" && o.method != "logs-clear" && o.logClearPreview.set || o.method != "logs-clear" && o.logClearRecreate.set {
		return o, errors.New("--preview/--recreate require compose logs-clear")
	}
	switch o.method {
	case "restart", "restart-status":
		if o.project.value == "" || o.file.set || o.plan.set || o.output.set || o.deployment.set || o.node.set || o.logClearRecreate.set {
			return o, errors.New("restart/restart-status requires -p PROJECT without deployment overrides")
		}
		if o.method == "restart" {
			if !(containerops.Selection{App: o.project.value, Service: o.container.service, Instance: o.container.instance.value}).Valid() || o.logClearPreview.value && o.operation.set || !o.logClearPreview.value && !lifecycle.ValidID(o.operation.value) {
				return o, errors.New("restart requires SERVICE and either --preview or --operation ID")
			}
		} else if o.logClearPreview.set || !lifecycle.ValidID(o.operation.value) {
			return o, errors.New("restart-status requires --operation ID")
		}
	case "exec", "exec-status":
		if o.project.value == "" || !lifecycle.ValidID(o.operation.value) || o.file.set || o.plan.set || o.output.set || o.deployment.set || o.node.set {
			return o, errors.New("exec/exec-status requires -p PROJECT --operation ID without deployment options")
		}
		if o.method == "exec" {
			if !(containerops.Selection{App: o.project.value, Service: o.container.service, Instance: o.container.instance.value}).Valid() || o.container.execSpec().Validate() != nil {
				return o, errors.New("exec requires SERVICE -- ARG [ARG ...] and valid -i/-t options")
			}
		}
	case "logs-clear":
		if o.project.value == "" || o.file.set || o.plan.set || o.output.set || o.deployment.set || o.node.set || o.logClearPreview.value == o.logClearRecreate.value || o.logClearPreview.value && o.operation.set || o.logClearRecreate.value && o.operation.value == "" {
			return o, errors.New("logs-clear requires -p PROJECT SERVICE and either --preview or explicit --recreate --operation ID")
		}
		if o.logClearRecreate.value && !(control.AppLogClearQuery{Selection: containerops.Selection{App: o.project.value}, Operation: o.operation.value}).Valid(false) {
			return o, errors.New("invalid log-clear operation")
		}
		if !(control.AppLogClearQuery{Selection: containerops.Selection{App: o.project.value, Service: o.container.service, Instance: o.container.instance.value}}).Valid(true) {
			return o, errors.New("invalid log-clear service/instance")
		}
	case "logs-clear-status":
		if !(control.AppLogClearQuery{Selection: containerops.Selection{App: o.project.value}, Operation: o.operation.value}).Valid(false) {
			return o, errors.New("invalid log-clear app/operation")
		}
		if o.project.value == "" || o.operation.value == "" || o.file.set || o.plan.set || o.output.set || o.deployment.set || o.node.set {
			return o, errors.New("logs-clear-status requires -p PROJECT --operation ID")
		}
	case "logs", "top", "stats", "inspect":
		if o.project.value == "" || o.file.set || o.plan.set || o.output.set || o.deployment.set || o.node.set {
			return o, errors.New("container query requires -p PROJECT and SERVICE without deployment options")
		}
		if err := o.container.finish(o.method, o.project.value); err != nil {
			return o, err
		}
	case "config":
		if o.project.set || o.tenant.set || o.deployment.set || o.node.set || o.output.set {
			return o, errors.New("config accepts only --file")
		}
	case "plan", "diff":
	case "up":
		if o.operation.value == "" || o.output.set || o.plan.set && (o.file.set || o.project.set || o.deployment.set || o.node.set) {
			return o, errors.New("up requires --operation ID and either --plan or Compose file/options")
		}
	case "resume":
		if o.operation.value == "" || o.file.set || o.plan.set || o.project.set || o.deployment.set || o.node.set || o.output.set {
			return o, errors.New("resume requires only the original --operation and tenant")
		}
	case "down":
		if o.operation.value == "" || o.project.value == "" || o.file.set || o.plan.set || o.output.set || o.deployment.set || o.node.set {
			return o, errors.New("down requires --operation ID -p PROJECT and tenant")
		}
	case "ps", "status":
		if o.file.set || o.plan.set || o.deployment.set || o.node.set || o.output.set || o.method == "status" && (!o.project.set || o.project.value == "" || o.operation.set && o.operation.value == "") {
			return o, errors.New("status requires -p PROJECT; ps/status do not accept file, node or deployment overrides")
		}
	case "wait":
		if o.operation.value == "" || o.project.value == "" || o.file.set || o.plan.set || o.output.set || o.deployment.set || o.node.set || o.condition.set && o.condition.value != "healthy" && o.condition.value != "retired" {
			return o, errors.New("wait requires --operation ID -p PROJECT and --condition healthy|retired")
		}
	default:
		return o, errors.New("compose command not implemented")
	}
	if o.plan.set && o.method != "up" || o.operation.set && o.method != "up" && o.method != "resume" && o.method != "down" && o.method != "wait" && o.method != "status" && o.method != "logs-clear" && o.method != "logs-clear-status" && o.method != "exec" && o.method != "exec-status" && o.method != "restart" && o.method != "restart-status" {
		return o, errors.New("--plan requires up; --operation requires up, down, resume, wait or status")
	}
	if o.condition.set && o.method != "wait" {
		return o, errors.New("--condition requires wait")
	}
	if o.sourceOperation.set && (o.method != "plan" && o.method != "diff" || o.sourceOperation.value == "" || o.file.set || o.project.set || o.deployment.set || o.node.set) {
		return o, errors.New("--source-operation requires plan/diff without new file or placement options")
	}
	if o.retrySource.set && o.method != "resume" {
		return o, errors.New("--retry-source requires compose resume")
	}
	if o.method != "up" && o.method != "resume" && (o.noInput || len(o.passwordFDs.values) != 0) {
		return o, errors.New("Group input options require up or resume")
	}
	return o, nil
}
func composeDocument(path string) ([]byte, error) {
	if path == "" {
		for _, name := range []string{"app.yaml", "app.yml", "docker-compose.yaml", "docker-compose.yml", "compose.yaml", "compose.yml"} {
			info, err := os.Stat(name)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() {
				return nil, errors.New("compose candidate must be a regular file")
			}
			if path != "" {
				return nil, errors.New("multiple Compose files; specify -f FILE")
			}
			path = name
		}
		if path == "" {
			return nil, errors.New("no Compose file; specify -f FILE")
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("compose requires a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, deployment.ArtifactMaxBytes+1))
	if err != nil || len(raw) > deployment.ArtifactMaxBytes {
		return nil, errors.New("compose input exceeds 4MiB")
	}
	return raw, nil
}
func runCompose(ctx context.Context, args []string, client userauth.Client, target mydcp.Peer, stored userauth.Stored, home string, out, diagnostic io.Writer) int {
	return runComposeDefaults(ctx, args, client, target, stored, home, cliprofile.Selection{}, out, diagnostic)
}

func runComposeDefaults(ctx context.Context, args []string, client userauth.Client, target mydcp.Peer, stored userauth.Stored, home string, defaults cliprofile.Selection, out, diagnostic io.Writer) int {
	o, err := parseComposeDefaults(args, diagnostic, defaults)
	if err != nil {
		return failure(diagnostic, err, 2)
	}
	if _, err := (cliprofile.Selection{Tenant: stored.TargetTenant}).CheckTenant(o.tenant.value, "", false); err != nil {
		return failure(diagnostic, err, 2)
	}
	tenant := o.tenant.value
	if tenant == "" {
		tenant = stored.Tenant
	}
	if tenant == "" {
		return failure(diagnostic, errors.New("compose requires --tenant or a selected tenant"), 2)
	}
	if o.method == "restart" || o.method == "restart-status" {
		return runTaskRestart(ctx, o, tenant, client, target, stored, home, out, diagnostic)
	}
	if o.method == "logs-clear" || o.method == "logs-clear-status" {
		return runLogClear(ctx, o, tenant, client, target, stored, home, out, diagnostic)
	}
	if o.method == "exec" || o.method == "exec-status" || containerReadMethod(o.method) && (o.container.follow.value || o.container.watch.value) {
		return runContainerStream(ctx, o, tenant, client, target, stored, home, out, diagnostic)
	}
	if containerReadMethod(o.method) {
		return runContainerRead(ctx, o, tenant, client, target, stored, out, diagnostic)
	}
	if o.method == "up" || o.method == "resume" {
		return runComposeUp(ctx, o, tenant, home, client, target, stored, out, diagnostic)
	}
	if o.method == "down" {
		return runComposeDown(ctx, o, tenant, home, client, target, stored, out, diagnostic)
	}
	if o.method == "wait" {
		return runComposeWait(ctx, o, tenant, client, target, stored, out, diagnostic)
	}
	if o.method == "plan" || o.method == "diff" {
		var artifact []byte
		if o.sourceOperation.set {
			parent, loadErr := userauth.LoadComposeSources(home, client, stored.Session, o.sourceOperation.value)
			if loadErr != nil {
				return failure(diagnostic, loadErr, 2)
			}
			if parent.Tenant != tenant {
				return failure(diagnostic, errors.New("original source preparation belongs to another tenant"), 2)
			}
			facts, sourceErr := metadataComposeSources(home, client, stored, parent)
			if sourceErr != nil {
				return composeSourceFailure(out, diagnostic, sourceErr)
			}
			artifact, err = fetchComposePlanSources(ctx, client, target, stored, tenant, sourceComposeOptions(o, parent), parent.Document, facts)
		} else {
			raw, readErr := composeDocument(o.file.value)
			if readErr != nil {
				return failure(diagnostic, readErr, 2)
			}
			artifact, err = fetchComposePlan(ctx, client, target, stored, tenant, o, raw)
		}
		if err != nil {
			return userFailure(diagnostic, err)
		}
		digest := sha256.Sum256(artifact)
		if o.output.set {
			if err = saveComposePlan(o.output.value, artifact); err != nil {
				return failure(diagnostic, err, 1)
			}
			return userOutput(out, diagnostic, struct {
				Schema uint8
				Path   string
				Digest [32]byte
			}{1, o.output.value, digest})
		}
		_, err = fmt.Fprintln(out, string(artifact))
		if err != nil {
			return failure(diagnostic, err, 1)
		}
		return 0
	}
	if o.method != "ps" && o.method != "status" {
		return failure(diagnostic, errors.New("unsupported remote compose command"), 2)
	}
	if o.method == "status" && o.operation.set {
		reply, err := client.AppOperation(ctx, target, stored.Session, tenant, control.AppOperationRequest{App: o.project.value, ID: o.operation.value})
		if err != nil {
			return userFailure(diagnostic, err)
		}
		status, code := "original-result", 0
		if !reply.AppOperation.Found {
			status, code = "unknown", 4
		}
		if userOutput(out, diagnostic, map[string]any{"schema": 1, "status": status, "operation": reply.AppOperation, "root_revision": reply.AppsRootRevision}) != 0 {
			return 1
		}
		return code
	}
	var apps []control.AppView
	cursor := ""
	var revision, catalogRevision uint64
	for {
		page, err := client.AppPage(ctx, target, stored.Session, tenant, cursor)
		if err != nil {
			return userFailure(diagnostic, err)
		}
		if cursor == "" {
			revision, catalogRevision = page.AppsRootRevision, page.RootRevision
		} else if revision != page.AppsRootRevision || catalogRevision != page.RootRevision {
			return failure(diagnostic, errors.New("app inventory or authority changed between pages"), 4)
		}
		for _, v := range page.Apps {
			if v.Tenant != tenant {
				return failure(diagnostic, errors.New("invalid app inventory scope"), 1)
			}
			if o.project.value == "" || v.App == o.project.value {
				apps = append(apps, v)
			}
		}
		if page.AppsNext == "" {
			break
		}
		if page.AppsNext <= cursor {
			return failure(diagnostic, errors.New("invalid app inventory cursor"), 1)
		}
		cursor = page.AppsNext
	}
	if o.method == "status" && len(apps) == 0 {
		return failure(diagnostic, errors.New("app not found"), 1)
	}
	return userOutput(out, diagnostic, struct {
		Schema              uint8
		Tenant              string
		RootRevision        uint64
		CatalogRootRevision uint64
		Apps                []control.AppView
	}{1, tenant, revision, catalogRevision, apps})
}

// A plan contains declaration metadata only. Publish it after a complete digest
// check, with private permissions and file/parent durability, never a partial part.
func saveComposePlan(path string, raw []byte) error {
	dir := filepath.Dir(path)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("plan destination must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(dir, ".mydc-plan-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(append(append([]byte(nil), raw...), '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
