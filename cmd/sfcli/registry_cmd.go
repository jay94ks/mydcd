// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
)

// sfcli registry: the tenant's built-in registries and external image
// sources (devel/design/cli-and-formats.md, 저장소·이미지·빌드).

func registryCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "registry",
		Short: "Built-in image registries and external image sources",
		Sub: []*cli.Command{
			{Name: "list", Short: "List the tenant's registries", Run: g.withSession(registryList(g))},
			{Name: "show", Args: "NAME", Short: "Show one registry", Run: g.withSession(registryShow(g))},
			registryCreateCommand(g),
			registryControlCommand(g, "start"),
			registryControlCommand(g, "stop"),
			registryDeleteCommand(g),
			registryGCCommand(g),
			registryPruneCommand(g),
			registryLoginCommand(g),
			registryExportCommand(g),
			registryImportCommand(g),
			externalCommand(g),
		},
	}
}

func init() {
	opKinds["registry-control"] = registryControlHandler
	opKinds["registry-maintenance"] = registryMaintenanceHandler
}

// registryStatus is the one-word state of a registry for people.
func registryStatus(row control.RegistryView) string {
	switch {
	case row.Deleted:
		return "deleted"
	case !row.Spec.Enabled && row.Active:
		return "stopping"
	case !row.Spec.Enabled:
		return "stopped"
	case row.Draining:
		return "draining"
	case row.Observation != nil:
		return "serving"
	}
	return "starting"
}

// registryConsumersShort names the limit that keeps a registry from
// starting: the server reserves its MaxRequests connections against the
// tenant's and the server's max consumers on its node, and a start report
// that does not fit is refused, so the registry stays "starting". Empty when
// both fit or the limits cannot be read.
func registryConsumersShort(ctx context.Context, s *session, tenant, node string, need int) string {
	var limits []tenancy.NodeLimit
	after := ""
	for range 4096 {
		reply, err := s.Client.Resources(ctx, s.Target, s.Stored.Session, userauth.ResourcesQuery{Tenant: tenant, After: after})
		if err != nil {
			return ""
		}
		for _, e := range reply.Items {
			if e.Limit != nil {
				limits = append(limits, *e.Limit)
			}
		}
		if reply.Next == "" || reply.Next == after {
			break
		}
		after = reply.Next
	}
	return consumersShort(limits, tenant, node, need)
}

func consumersShort(limits []tenancy.NodeLimit, tenant, node string, need int) string {
	for _, l := range limits {
		if l.Node != node || l.Tenant != tenant && l.Tenant != "" || l.MaxConsumers >= need {
			continue
		}
		if l.Tenant == "" {
			return fmt.Sprintf("the registry needs %d connections on %s but that server allows %d; a system administrator raises it with 'sfcli node quota set %s --consumers %d'", need, node, l.MaxConsumers, node, need)
		}
		return fmt.Sprintf("the registry needs %d connections on %s but tenant %s allows %d there; a system administrator raises it with 'sfcli tenant quota set %s %s --consumers %d'", need, node, tenant, l.MaxConsumers, tenant, node, need)
	}
	return ""
}

// readRegistryRows reads every registry of the tenant as one snapshot.
func readRegistryRows(ctx context.Context, s *session, tenant string) ([]control.RegistryView, error) {
	var rows []control.RegistryView
	var root, revision, maintenance uint64
	after := ""
	for {
		reply, err := s.Client.RegistryPage(ctx, s.Target, s.Stored.Session, tenant, after)
		if err != nil {
			return nil, err
		}
		if reply.Tenant != tenant || len(reply.Registries) > 8 {
			return nil, errors.New("the server sent an invalid registry page")
		}
		if after == "" {
			root, revision, maintenance = reply.RegistriesRootRevision, reply.RegistriesRevision, reply.RegistryMaintenanceRootRevision
		} else if root != reply.RegistriesRootRevision || revision != reply.RegistriesRevision || maintenance != reply.RegistryMaintenanceRootRevision {
			return nil, errors.New("registries changed while reading; run the command again")
		}
		for _, row := range reply.Registries {
			if row.Spec.Validate(s.Client.Cluster) != nil || row.Spec.Tenant != tenant || row.Spec.Key() <= after || row.Revision == 0 {
				return nil, errors.New("the server sent an invalid registry")
			}
			rows = append(rows, row)
			after = row.Spec.Key()
		}
		if reply.RegistriesNext == "" {
			return rows, nil
		}
		if len(rows) > 4096 || reply.RegistriesNext != after {
			return nil, errors.New("the server sent an invalid registry page cursor")
		}
	}
}

func findRegistryRow(ctx context.Context, s *session, tenant, name string) (control.RegistryView, error) {
	rows, err := readRegistryRows(ctx, s, tenant)
	if err != nil {
		return control.RegistryView{}, err
	}
	for _, row := range rows {
		if row.Spec.ID == name && !row.Deleted {
			return row, nil
		}
	}
	return control.RegistryView{}, fmt.Errorf("no registry %q in tenant %s", name, tenant)
}

func oneName(args []string, what string) (string, error) {
	if len(args) != 1 {
		return "", cli.Usagef("needs one %s", what)
	}
	if !lifecycle.ValidID(args[0]) {
		return "", cli.Usagef("%q is not a valid %s", args[0], what)
	}
	return args[0], nil
}

func registryList(g *globals) func(*cli.Context, *session, []string) error {
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
		rows, err := readRegistryRows(ctx, s, tenant)
		if err != nil {
			return err
		}
		live := []control.RegistryView{}
		for _, row := range rows {
			if !row.Deleted {
				live = append(live, row)
			}
		}
		return cli.Print(c.Out, g.output.Format(), live, func() cli.Rows {
			t := cli.Rows{Header: []string{"name", "status", "node", "address", "volume", "revision"}}
			for _, r := range live {
				t.Add(r.Spec.ID, registryStatus(r), r.Spec.Node, r.Spec.Authority, r.Spec.Volume.ID, r.Revision)
			}
			return t
		})
	}
}

func registryShow(g *globals) func(*cli.Context, *session, []string) error {
	return func(c *cli.Context, s *session, args []string) error {
		name, err := oneName(args, "registry name")
		if err != nil {
			return err
		}
		tenant, err := g.Tenant(s, true)
		if err != nil {
			return err
		}
		ctx, cancel := g.Deadline(c)
		defer cancel()
		row, err := findRegistryRow(ctx, s, tenant, name)
		if err != nil {
			return err
		}
		status, waiting := registryStatus(row), ""
		if status == "starting" {
			waiting = registryConsumersShort(ctx, s, tenant, row.Spec.Node, row.Spec.MaxRequests)
		}
		return cli.Print(c.Out, g.output.Format(), struct {
			Status  string `json:"status"`
			Waiting string `json:"waiting,omitempty"`
			control.RegistryView
		}{status, waiting, row}, nil)
	}
}

// defaultRegistryLimits are the limits of a new registry; blob storage
// defaults to the Volume's capacity.
func defaultRegistryLimits(s *registry.Specification, capacity uint64) {
	total := int64(50 << 30)
	if capacity > 0 {
		total = int64(min(capacity, 1<<62))
	}
	s.Metadata = registry.MetadataLimits{ManifestBytes: 4 << 20, Records: 4096, TotalBytes: 64 << 20}
	s.Blobs = registry.BlobLimits{BlobBytes: min(4<<30, total), TotalBytes: total, Records: 16384}
	s.Budget = workload.Resources{CPU: 1000, Memory: 256 << 20}
	s.MaxRequests, s.MaxHeaderBytes, s.RequestTimeoutMS, s.TokenSeconds = 64, 16<<10, 60000, 300
}

func findVolumeRow(ctx context.Context, s *session, tenant, name string) (control.VolumeView, error) {
	var found []control.VolumeView
	after := ""
	for range 4096 {
		reply, err := s.Client.VolumePage(ctx, s.Target, s.Stored.Session, tenant, after)
		if err != nil {
			return control.VolumeView{}, err
		}
		for _, v := range reply.Items {
			if v.Scope.Tenant == tenant && v.Scope.ID == name && v.Scope.App == "" && v.Scope.Registry == "" {
				found = append(found, v)
			}
		}
		if reply.Next == "" || reply.Next == after {
			break
		}
		after = reply.Next
	}
	if len(found) != 1 {
		return control.VolumeView{}, fmt.Errorf("no fixed Volume %q in tenant %s; register a storage directory as one with 'sfcli volume register'", name, tenant)
	}
	return found[0], nil
}

func registryCreateCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var volume, authority, node, address string
	var maxSize cli.Size
	return &cli.Command{
		Name:  "create",
		Args:  "NAME",
		Short: "Create a registry on a fixed Volume",
		Long: `Creates a built-in registry that stores its images on a fixed Volume of the
tenant and serves them at --authority (host[:port]). TLS uses the cluster
certificate store's certificate for the authority host, so that host must be
inside a registered domain (sfcli domain) with a linked certificate. It runs on
the Volume's server and starts right away.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.StringVar(&volume, "volume", "", "fixed Volume that stores the images (required)")
			fs.StringVar(&authority, "authority", "", "address clients use, host[:port] (required)")
			fs.StringVar(&node, "node", "", "server to run on (default: the Volume's server)")
			fs.StringVar(&address, "address", "", "listen address IP:port (default 0.0.0.0 and the authority's port)")
			fs.Var(&maxSize, "max-size", "space for images, such as 50GiB (default: the Volume's size)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "registry name")
			if err != nil {
				return err
			}
			if volume == "" || authority == "" {
				return cli.Usagef("--volume and --authority are required")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			rows, err := readRegistryRows(ctx, s, tenant)
			if err != nil {
				return err
			}
			if slices.ContainsFunc(rows, func(r control.RegistryView) bool { return r.Spec.ID == name }) {
				return fmt.Errorf("registry %q already exists (or was deleted); choose another name", name)
			}
			v, err := findVolumeRow(ctx, s, tenant, volume)
			if err != nil {
				return err
			}
			spec := registry.Specification{Schema: 1, Tenant: tenant, ID: name, Node: v.Owner.Node, Volume: v.Scope, Enabled: true, Authority: authority, Address: address}
			defaultRegistryLimits(&spec, v.CapacityBytes)
			if maxSize > 0 {
				spec.Blobs.TotalBytes = int64(min(uint64(maxSize), 1<<62))
				spec.Blobs.BlobBytes = min(spec.Blobs.BlobBytes, spec.Blobs.TotalBytes)
			}
			if node != "" {
				spec.Node = node
			}
			if spec.Address == "" {
				spec.Address = "0.0.0.0:" + authorityPort(authority)
			}
			if err = spec.Validate(s.Client.Cluster); err != nil {
				return cli.Usagef("the registry is not valid: --authority host[:port] whose port matches --address IP:port and a size the Volume can hold")
			}
			if short := registryConsumersShort(ctx, s, tenant, spec.Node, spec.MaxRequests); short != "" {
				return errors.New(short)
			}
			fmt.Fprintf(c.Err, "Create registry %s in %s on %s at %s (Volume %s).\n", name, tenant, spec.Node, authority, volume)
			if err = g.Prompter(c).Confirm("Create it?"); err != nil {
				return err
			}
			opID := id.Get()
			_, err = g.send(c, s, change{Summary: "registry create " + name, ID: opID, Action: "put-registry", Payload: control.RegistryPut{Spec: spec}})
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "registry %s created (%s); it starts on %s\n", name, opID, spec.Node)
			return nil
		}),
	}
}

func authorityPort(a string) string {
	if ap, err := netip.ParseAddrPort(a); err == nil {
		return fmt.Sprint(ap.Port())
	}
	if i := strings.LastIndexByte(a, ':'); i >= 0 && !strings.Contains(a[i:], "]") {
		return a[i+1:]
	}
	return "443"
}

// registryReached reports whether the registry reached what verb asked.
func registryReached(row control.RegistryView, verb string) bool {
	if verb == "start" {
		return registryStatus(row) == "serving"
	}
	return registryStatus(row) == "stopped"
}

func registryControlCommand(g *globals, verb string) *cli.Command {
	var id cli.IDFlag
	var rev cli.RevisionFlag
	var wait waitFlags
	short := map[string]string{"start": "Start a stopped registry and wait until it serves", "stop": "Stop a registry and wait until it has stopped (images are kept)"}[verb]
	return &cli.Command{
		Name:  verb,
		Args:  "NAME",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.Var(&rev, "if-revision", "only if the registry is still at this `revision`")
			wait.register(fs)
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "registry name")
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			plan, err := s.Client.PlanRegistryAction(ctx, s.Target, s.Stored.Session, tenant, control.RegistryActionQuery{Action: verb + "-registry", ID: name})
			if err != nil {
				return err
			}
			expected, err := rev.Resolve(func() (uint64, error) { return plan.Expected, nil })
			if err != nil {
				return err
			}
			if registryReached(plan.Current, verb) {
				fmt.Fprintf(c.Out, "registry %s is already %s\n", name, registryStatus(plan.Current))
				return nil
			}
			if verb == "stop" {
				fmt.Fprintf(c.Err, "Stop registry %s on %s. Pulls from it fail until it starts again; its images are kept.\n", name, plan.Current.Spec.Node)
				if err = g.Prompter(c).Confirm("Stop it?"); err != nil {
					return err
				}
			}
			opID := id.Get()
			_, err = g.send(c, s, change{Kind: "registry-control", Summary: "registry " + verb + " " + name, ID: opID, Action: verb + "-registry", Expected: expected, Epoch: plan.Epoch, Payload: control.RegistrySelection{Tenant: tenant, ID: name}, Async: true})
			if err != nil {
				return err
			}
			if wait.noWait {
				fmt.Fprintf(c.Out, "accepted %s; check with 'sfcli op show %s'\n", opID, opID)
				return nil
			}
			_, line, err := g.follow(c, opID, func(c *cli.Context) (cli.State, string, error) {
				return registryProgress(c, g, s, tenant, name, verb)
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "registry %s %s\n", name, line)
			return nil
		}),
	}
}

func registryProgress(c *cli.Context, g *globals, s *session, tenant, name, verb string) (cli.State, string, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	row, err := findRegistryRow(ctx, s, tenant, name)
	if err != nil {
		return "", "", err
	}
	st := cli.Accepted
	if registryReached(row, verb) {
		st = cli.Done
	}
	return st, registryStatus(row), nil
}

// opTarget splits an op summary "registry stop NAME" into its words.
func opWords(op cli.Op) []string { return strings.Fields(op.Summary) }

func registryControlHandler(g *globals) cli.Handler {
	base := changeHandler(g, nil, true)
	then := func(call func(*cli.Context, cli.Op) (cli.State, string, error)) func(*cli.Context, cli.Op) (cli.State, string, error) {
		return func(c *cli.Context, op cli.Op) (cli.State, string, error) {
			st, line, err := call(c, op)
			words := opWords(op)
			if err != nil || st != cli.Accepted || len(words) != 3 {
				return st, line, err
			}
			s, err := g.opSession(c, op)
			if err != nil {
				return "", "", err
			}
			defer s.Close()
			return registryProgress(c, g, s, op.Tenant, words[2], words[1])
		}
	}
	return cli.Handler{Show: then(base.Show), Resume: then(base.Resume)}
}

func registryDeleteCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var rev cli.RevisionFlag
	return &cli.Command{
		Name:  "delete",
		Args:  "NAME",
		Short: "Delete a stopped registry (its Volume and data are kept)",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.Var(&rev, "if-revision", "only if the registry is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "registry name")
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			row, err := findRegistryRow(ctx, s, tenant, name)
			if err != nil {
				return err
			}
			if row.Spec.Enabled || row.Active {
				return fmt.Errorf("registry %s is %s; stop it first with 'sfcli registry stop %s'", name, registryStatus(row), name)
			}
			expected, err := rev.Resolve(func() (uint64, error) { return row.Revision, nil })
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Delete registry %s. The name cannot be used again; Volume %s and its data are kept.\n", name, row.Spec.Volume.ID)
			if err = g.Prompter(c).Confirm("Delete it?"); err != nil {
				return err
			}
			opID := id.Get()
			if _, err = g.send(c, s, change{Summary: "registry delete " + name, ID: opID, Action: "delete-registry", Expected: expected, Payload: control.RegistrySelection{Tenant: tenant, ID: name}}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "registry %s deleted (%s)\n", name, opID)
			return nil
		}),
	}
}

// maintenanceState maps a registry maintenance status to the op index.
func maintenanceState(st control.RegistryMaintenanceStatus) (cli.State, string) {
	line := st.State
	if st.Result != nil {
		line += " (" + st.Result.Code
		if st.Result.ReclaimedBytes > 0 {
			line += ", freed " + cli.Size(st.Result.ReclaimedBytes).String()
		}
		line += ")"
	}
	switch st.State {
	case "done":
		return cli.Done, line
	case "failed":
		return cli.Failed, line
	}
	return cli.Accepted, line
}

func maintenanceProgress(c *cli.Context, g *globals, s *session, tenant, operation string) (cli.State, string, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	reply, err := s.Client.RegistryMaintenance(ctx, s.Target, s.Stored.Session, tenant, false, control.RegistryMaintenanceQuery{Operation: operation})
	if err != nil {
		return "", "", err
	}
	if reply.RegistryMaintenanceStatus == nil {
		return cli.Accepted, "waiting for the server", nil
	}
	st, line := maintenanceState(*reply.RegistryMaintenanceStatus)
	return st, line, nil
}

func registryMaintenanceHandler(g *globals) cli.Handler {
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
			return maintenanceProgress(c, g, s, op.Tenant, op.ID)
		}
	}
	return cli.Handler{Show: then(base.Show), Resume: then(base.Resume)}
}

// sendMaintenance sends a planned gc/delete/prune change and follows it.
func sendMaintenance(c *cli.Context, g *globals, s *session, tenant, summary, opID string, plan control.RegistryMaintenancePlan, wait waitFlags) error {
	payload := plan.Change
	payload.Operation = opID
	_, err := g.send(c, s, change{Kind: "registry-maintenance", Summary: summary, ID: opID, Action: plan.Action, Expected: plan.Expected, Epoch: plan.Epoch, Payload: payload, Async: true})
	if err != nil {
		return err
	}
	if wait.noWait {
		fmt.Fprintf(c.Out, "accepted %s; check with 'sfcli op show %s'\n", opID, opID)
		return nil
	}
	_, line, err := g.follow(c, opID, func(c *cli.Context) (cli.State, string, error) {
		return maintenanceProgress(c, g, s, tenant, opID)
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "%s: %s\n", summary, line)
	return nil
}

func registryGCCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var wait waitFlags
	return &cli.Command{
		Name:  "gc",
		Args:  "NAME",
		Short: "Free the space of image layers no image uses any more",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			wait.register(fs)
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "registry name")
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			reply, err := s.Client.RegistryMaintenance(ctx, s.Target, s.Stored.Session, tenant, true, control.RegistryMaintenanceQuery{Action: "gc-registry", ID: name})
			if err != nil {
				return err
			}
			if reply.RegistryMaintenancePlan == nil {
				return errors.New("the server sent no gc plan")
			}
			return sendMaintenance(c, g, s, tenant, "registry gc "+name, id.Get(), *reply.RegistryMaintenancePlan, wait)
		}),
	}
}

// listFlag is a repeatable string option.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func registryPruneCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var wait waitFlags
	var repos, excludeTags, protect listFlag
	var keep uint
	var olderThan time.Duration
	var untagged, gc, external, dryRun bool
	return &cli.Command{
		Name:  "prune",
		Args:  "NAME",
		Short: "Delete old images that match conditions",
		Long: `Lists the images that match the conditions, asks, then deletes them.
Images that apps use are kept. --external prunes an external source instead
of a built-in registry.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.Var(&repos, "repository", "only this `repository` (repeatable; default all)")
			fs.UintVar(&keep, "keep", 0, "keep this many newest images per repository")
			fs.DurationVar(&olderThan, "older-than", 0, "only images uploaded at least this long ago, such as 720h")
			fs.Var(&excludeTags, "exclude-tag", "never delete this `tag` (repeatable)")
			fs.BoolVar(&untagged, "untagged", false, "also delete images without a tag")
			fs.Var(&protect, "protect", "never delete this `digest` (repeatable)")
			fs.BoolVar(&gc, "gc", false, "free the space afterwards (built-in registries only)")
			fs.BoolVar(&external, "external", false, "NAME is an external source")
			fs.BoolVar(&dryRun, "dry-run", false, "only list what would be deleted")
			wait.register(fs)
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "registry name")
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			cond := registryclient.PruneConditions{Repositories: slices.Sorted(slices.Values(repos)), KeepRecentPerRepository: uint32(keep), ExcludeTags: excludeTags, IncludeUntagged: untagged, ProtectedDigests: protect, GC: gc}
			if olderThan > 0 {
				cond.Before = uint64(time.Now().Add(-olderThan).Unix())
			}
			if !cond.Valid() || external && gc {
				return cli.Usagef("invalid conditions: repositories and tags must be valid names, digests sha256:..., and --gc only for built-in registries")
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			doc, err := collectRegistryPrune(ctx, s, tenant, name, external, cond)
			if err != nil {
				return err
			}
			if g.output.Format() != cli.Table || dryRun {
				if err = cli.Print(c.Out, g.output.Format(), doc.Items, func() cli.Rows {
					t := cli.Rows{Header: []string{"repository", "reference", "digest"}}
					for _, r := range doc.Items {
						t.Add(r.Image.Repository, r.Image.Reference, r.Image.Digest)
					}
					return t
				}); err != nil || dryRun {
					return err
				}
			}
			if len(doc.Items) == 0 {
				fmt.Fprintln(c.Out, "nothing to delete")
				return nil
			}
			fmt.Fprintf(c.Err, "Delete %d images from %s (%d kept because they are in use or protected).\n", len(doc.Items), name, len(doc.Retained))
			if err = g.Prompter(c).Confirm("Delete them?"); err != nil {
				return err
			}
			return sendMaintenance(c, g, s, tenant, "registry prune "+name, id.Get(), doc.Plan, wait)
		}),
	}
}

type registryPruneDocument struct {
	Plan     control.RegistryMaintenancePlan
	Items    []control.RegistryPruneRow
	Retained []registryclient.PruneRetained
}

// collectRegistryPrune reads the signed prune preview and its rows, and
// checks the rows against the preview's digest.
func collectRegistryPrune(ctx context.Context, s *session, tenant, id string, external bool, conditions registryclient.PruneConditions) (registryPruneDocument, error) {
	doc := registryPruneDocument{Items: []control.RegistryPruneRow{}, Retained: []registryclient.PruneRetained{}}
	q := control.RegistryPruneQuery{ID: id, External: external, Conditions: &conditions}
	for _, part := range []string{"items", "retained"} {
		q.Part = part
		after := ""
		for pages := 0; ; pages++ {
			if pages > 4096 {
				return doc, errors.New("too many prune pages")
			}
			view, err := s.Client.RegistryPrune(ctx, s.Target, s.Stored.Session, tenant, q, after, false)
			if err != nil {
				return doc, err
			}
			if q.Fact == nil {
				doc.Plan = view.Plan
				fact := view.Plan.Change.Prune.Fact
				q.Fact = &fact
			}
			doc.Items = append(doc.Items, view.Page.Rows...)
			doc.Retained = append(doc.Retained, view.Page.Retained...)
			if len(doc.Items) > registryclient.MaxCatalogueNames || len(doc.Retained) > 2*registryclient.MaxCatalogueNames {
				return doc, errors.New("too many images to prune at once; narrow it with --repository")
			}
			if view.Page.Next == "" {
				break
			}
			if view.Page.Next == after {
				return doc, errors.New("the server sent an invalid prune page cursor")
			}
			after = view.Page.Next
		}
	}
	p, f := doc.Plan, doc.Plan.Change
	if p.Action != control.RegistryPruneAction || p.Tenant != tenant || f.Prune == nil || f.RegistryID() != id || (f.External != nil) != external ||
		uint32(len(doc.Items)) != f.Prune.Fact.Items || uint32(len(doc.Retained)) != f.Prune.Fact.Retained || control.RegistryPrunePublicDigest(doc.Items, doc.Retained) != f.Prune.Fact.Public {
		return doc, errors.New("the prune preview does not match its rows; run the command again")
	}
	return doc, nil
}

func registryLoginCommand(g *globals) *cli.Command {
	var repository string
	var push, catalog bool
	return &cli.Command{
		Name:  "login",
		Args:  "NAME",
		Short: "Print a short-lived registry password for docker login",
		Long: `Prints a short-lived password for one repository of a built-in registry on
standard output, for example:

  sfcli registry login shop-registry --repository shop/web --push | \
    docker login registry.shop.test --username "$(sfcli whoami)" --password-stdin

The password is never printed to a terminal. The user name is the one you
are logged in as.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&repository, "repository", "", "repository the password is for (required unless --catalog)")
			fs.BoolVar(&push, "push", false, "allow push as well as pull")
			fs.BoolVar(&catalog, "catalog", false, "list repositories instead (no pull or push)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "registry name")
			if err != nil {
				return err
			}
			if f, ok := c.Out.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
				return cli.Usagef("the password is not printed to a terminal; pipe it to 'docker login --password-stdin'")
			}
			var repo string
			var actions []string
			switch {
			case catalog && (repository != "" || push):
				return cli.Usagef("--catalog takes no --repository or --push")
			case catalog:
				repo, actions = "**", []string{"catalog"}
			case repository == "":
				return cli.Usagef("--repository is required")
			default:
				scope := "repository:" + repository + ":pull"
				if push {
					scope += ",push"
				}
				if repo, actions, err = registry.RequestedScope(scope); err != nil {
					return cli.Usagef("%q is not a valid repository", repository)
				}
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			reply, err := s.Client.RegistryCredential(ctx, s.Target, s.Stored.Session, tenant, userauth.RegistryCredentialRequest{ID: name, Repository: repo, Actions: actions})
			defer clear(reply.RegistryCredential)
			if err != nil {
				return err
			}
			if err = checkRegistryCredential(s, reply, tenant, name, repo, actions); err != nil {
				return fmt.Errorf("%w; nothing was printed", err)
			}
			if _, err = c.Out.Write(append(slices.Clone(reply.RegistryCredential), '\n')); err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "password for %s as %s, valid until %s\n", reply.RegistryAuthority, s.Stored.Username, time.Unix(reply.RegistryCredentialExpires, 0).Local().Format("15:04"))
			return nil
		}),
	}
}
