// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

const composeFixture = `
name: php-mysql
services:
  web:
    image: docker.io/library/php@sha256:DIGEST
    cpus: 0.5
    mem_limit: 128m
    command: [php, app.php]
    environment: {DB_HOST: db, DB_PASSWORD_FILE: /run/secrets/db-password}
    secrets: [db-password]
    depends_on: {db: {condition: service_healthy}}
    networks: {app: {ipv4_address: 10.240.10.10}}
    x-sfc:
      node: node-a
      secrets: {from: [defaults, group/common, overrides]}
      ready: {http: /readyz, port: 8080}
  db:
    image: docker.io/library/mysql@sha256:DIGEST
    cpus: 1
    mem_limit: 256m
    command: [mysqld]
    secrets: [db-password]
    volumes: [mysql-data:/var/lib/mysql]
    healthcheck: {test: [CMD, probe], interval: 5s, timeout: 3s, retries: 12, start_period: 60s}
    networks: {app: {ipv4_address: 10.240.20.10}}
    x-sfc:
      node: node-b
      secrets: {from: [defaults, group/common, group/db-admin]}
networks:
  app:
    x-sfc:
      mtu: 1280
      pools:
        node-a: {cidr: 10.240.10.0/24, gateway: 10.240.10.1}
        node-b: {cidr: 10.240.20.0/24, gateway: 10.240.20.1}
      tunnel_addresses: {node-a: 10.240.30.1/32, node-b: 10.240.30.2/32}
volumes:
  mysql-data:
    x-sfc: {node: node-b}
secrets:
  db-password:
    x-sfc: {key: DB_PASSWORD}
`

func smallCompose(t *testing.T) Compose {
	t.Helper()
	c, e := ParseCompose([]byte(strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64))))
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func contextFor(t *testing.T, f *fixture) PlanningContext {
	t.Helper()
	networks, e := tenancy.New(f.cluster)
	if e != nil {
		t.Fatal(e)
	}
	networks = networks.WithServers(map[string]netip.Addr{"node-a": netip.MustParseAddr("10.254.240.1"), "node-b": netip.MustParseAddr("10.254.240.2")})
	return PlanningContext{Cluster: f.cluster, Actor: "alice", Tenant: "tenant", Project: "php-mysql", Deployment: "deploy", Nodes: map[string]PlanningNode{
		"node-a": {Key: public(f.na), Generation: 3, Revision: 10, Underlay: "192.0.2.11", Voter: true, Capacity: workload.Resources{CPU: 4e9, Memory: 4 << 30}, DefaultCPU: 500000000, DefaultMemory: 128 << 20},
		"node-b": {Key: public(f.nb), Generation: 7, Revision: 18, Underlay: "192.0.2.12", Voter: true, Capacity: workload.Resources{CPU: 4e9, Memory: 4 << 30}, DefaultCPU: 500000000, DefaultMemory: 128 << 20},
	}, Networks: networks, Volumes: f.v, Features: map[string]bool{"core": true, "volumes": true, "inputs": true}}
}

// frozenCompose is historical schema1 input, never a new app submission.
func frozenCompose(t *testing.T) Compose {
	t.Helper()
	raw, e := os.ReadFile("testdata/frozen-schema1-compose.yaml")
	if e != nil {
		t.Fatal(e)
	}
	s := strings.NewReplacer("<STABLE_DEPLOYMENT_ID>", "deploy", "<WEB_IMAGE_DIGEST>", strings.Repeat("b", 64), "<DB_IMAGE_DIGEST>", strings.Repeat("c", 64), "<REGISTRY_IMAGE_DIGEST>", strings.Repeat("d", 64), "tenant-demo", "tenant").Replace(string(raw))
	c, e := ParseCompose([]byte(s))
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func stepMap(b Blueprint) map[string]Step {
	out := map[string]Step{}
	for _, s := range b.Steps() {
		out[s.Key] = s
	}
	return out
}

func TestComposeCanonicalFormsPreserveOmittedAndEmptyCommands(t *testing.T) {
	first := smallCompose(t)
	base := strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64))
	alternative := strings.ReplaceAll(base, "cpus: 0.5", "cpus: 0.500000000")
	alternative = strings.ReplaceAll(alternative, "mem_limit: 128m", "mem_limit: 134217728")
	alternative = strings.Replace(alternative, "environment: {DB_HOST: db, DB_PASSWORD_FILE: /run/secrets/db-password}", "environment: [DB_PASSWORD_FILE=/run/secrets/db-password, DB_HOST=db]", 1)
	second, e := ParseCompose([]byte("# syntax only\n" + alternative))
	if e != nil {
		t.Fatal(e)
	}
	a, _ := first.Digest()
	b, _ := second.Digest()
	if a != b {
		t.Fatal("semantic formatting changed artifact")
	}
	for _, body := range []string{"image: docker.io/library/php@sha256:" + strings.Repeat("a", 64), "image: docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "\n    command: []"} {
		c, e := ParseCompose([]byte("name: example\nservices:\n  one:\n    " + body + "\n"))
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(body, "[]") != (c.Services["one"].Command != nil) {
			t.Fatal("omitted/empty override collapsed")
		}
	}
}

func TestComposeRejectsUnknownAliasesDuplicateKeysAndHiddenInputs(t *testing.T) {
	base := "name: app\nservices:\n  web:\n    image: docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "\n"
	cases := []string{
		base + "    build: .\n", base + "    privileged: true\n", base + "    command: echo hello\n", base + "    environment: [INHERIT_ME]\n", base + "    environment: {X: true}\n", base + "    volumes: [/etc:/data]\n", base + "    ports: ['65536:80']\n", base + "    command: ['$HOST_SECRET']\n", base + "    depends_on: {missing: {condition: service_started}}\n",
		base + "x-sfc: {schema: 0}\n", base + "x-sfc: {schema: 2}\n", base + "version: '3.8'\n", base + "---\nname: other\n", base + "name: duplicate\n", base + "x-sfc: {password: hidden-private-marker}\n",
		"name: app\nservices:\n  web: &w {image: 'docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "'}\n  other: *w\n",
		base + "    depends_on: {web: {condition: service_started}}\n",
	}
	for i, body := range cases {
		_, e := ParseCompose([]byte(body))
		if e == nil {
			t.Fatalf("invalid case %d accepted", i)
		}
		if strings.Contains(e.Error(), "hidden-private-marker") {
			t.Fatal("diagnostic echoed private input")
		}
	}
	_, e := ParseCompose(bytes.Repeat([]byte{'x'}, (4<<20)+1))
	deny(t, e)
}

func TestComposeFullSingleFileRetainsAllDeclarationsAndScopeOrder(t *testing.T) {
	c := frozenCompose(t)
	raw, e := c.Canonical()
	if e != nil {
		t.Fatal(e)
	}
	if c.Sfc.Vault == nil || c.Sfc.Delivery == nil || !c.Sfc.Delivery.Enabled || !c.Sfc.Registries["private"].Enabled || !c.Networks["app"].Sfc.DNS.Enabled {
		t.Fatal("declared feature lost")
	}
	web := c.Services["web"]
	if len(web.Sfc.Sources) != 3 || web.Sfc.Sources[1].Group != "common" || web.Sfc.Sources[2].Secret != "web-runtime-overrides" || !bytes.Contains(raw, []byte("service-final-keyset")) {
		t.Fatal("ordered sources or references lost")
	}
	f := makeFixture(t)
	ctx := contextFor(t, f)
	ctx.Project = c.Name
	ctx.Features["network-services"] = true
	ctx.Features["registry"] = true
	ctx.Features["git-cd"] = true
	b, e := Compile(c, f.c, ctx)
	if e != nil {
		t.Fatal(e)
	}
	kinds := map[string]int{}
	for _, step := range b.Steps() {
		kinds[step.Kind]++
	}
	for _, kind := range []string{"bridge", "tunnel", "dns", "namespace", "volume", "inputs", "task", "ingress", "registry", "delivery"} {
		if kinds[kind] == 0 {
			t.Fatal("missing declared graph kind", kind)
		}
	}
	n, e := b.Inputs("web", "web-task", 17, public(private(30)))
	if e != nil {
		t.Fatal(e)
	}
	if n.Generation != 17 || n.Sources[1].Object != "group-php-mysql-common" || n.Sources[2].Object != "secret-web-runtime-overrides" || len(n.Files) != 1 {
		t.Fatal("alias/projection resolver lost declaration")
	}
	uses, err := b.ApprovalUses(public(private(30)))
	if err != nil {
		t.Fatal(err)
	}
	for realm, use := range realmUses(n) {
		if !slices.ContainsFunc(uses[realm], func(v secrets.Use) bool { return useEqual(v, use) }) {
			t.Fatal("approval plan drifted from real input aliases/source order", realm)
		}
	}
	if _, err := b.Inputs("web", "web-task", 0, public(private(30))); err == nil {
		t.Fatal("metadata planning weakened actual generation requirement")
	}
}

func TestComposeRejectsUnsafePoliciesAndVaultCycles(t *testing.T) {
	c := frozenCompose(t)
	for _, change := range []func(*Compose){
		func(c *Compose) { c.Sfc.Delivery.Source.Repository = "https://user:private@example.invalid/repo.git" },
		func(c *Compose) { c.Sfc.Delivery.Source.Path = "../outside" },
		func(c *Compose) { n := c.Networks["app"]; n.Sfc.RuntimeChanges.Restart = true; c.Networks["app"] = n },
		func(c *Compose) {
			r := c.Sfc.Registries["private"]
			r.Trusted = true
			c.Sfc.Registries["private"] = r
		},
		func(c *Compose) {
			g := c.Sfc.Vault.Tree.Groups["common"]
			g.Parent = "missing"
			c.Sfc.Vault.Tree.Groups["common"] = g
		},
	} {
		raw, _ := json.Marshal(c)
		var copy Compose
		_ = json.Unmarshal(raw, &copy)
		change(&copy)
		_, e := copy.Canonical()
		deny(t, e)
	}
	cycle := smallCompose(t)
	web := cycle.Services["web"]
	db := cycle.Services["db"]
	db.DependsOn = Dependencies{"web": {"service_started"}}
	cycle.Services["web"] = web
	cycle.Services["db"] = db
	_, e := cycle.Canonical()
	deny(t, e)
}

func TestBlueprintBuildsHealthyDAGAndRetainedReverseOrderWithoutEffects(t *testing.T) {
	f := makeFixture(t)
	ctx := contextFor(t, f)
	c := smallCompose(t)
	before, _ := c.Canonical()
	networkBefore, _ := ctx.Networks.Encode()
	volumeBefore, _ := f.v["tenant/php-mysql/mysql-data"].Encode()
	b, e := Compile(c, f.c, ctx)
	if e != nil {
		t.Fatal(e)
	}
	after, _ := c.Canonical()
	networkAfter, _ := ctx.Networks.Encode()
	volumeAfter, _ := f.v["tenant/php-mysql/mysql-data"].Encode()
	if !bytes.Equal(before, after) || !bytes.Equal(networkBefore, networkAfter) || !bytes.Equal(volumeBefore, volumeAfter) {
		t.Fatal("read-only plan changed declaration/reservations")
	}
	keys := map[string]int{}
	for i, s := range b.Steps() {
		keys[s.Key] = i
		for _, d := range s.Dependencies {
			if index, ok := keys[d.Key]; !ok || index >= i {
				t.Fatal("not topological")
			}
		}
	}
	web := ResourceKey("task", "tenant", "php-mysql", "web")
	db := ResourceKey("task", "tenant", "php-mysql", "db")
	steps := stepMap(b)
	if !slices.Contains(steps[web].Dependencies, Dependency{db, Healthy}) || steps[db].Completion != Healthy {
		t.Fatal("DB Running substituted for readiness")
	}
	reverse := b.ReleaseOrder()
	positions := map[string]int{}
	for i, s := range reverse {
		positions[s.Key] = i
	}
	volume := ResourceKey("volume", "tenant", "php-mysql", "mysql-data")
	if positions[web] >= positions[db] || positions[db] >= positions[volume] || !steps[volume].Retain {
		t.Fatal("unsafe release order")
	}
	digest := b.Digest()
	view := b.Steps()
	view[0].Goal[0] = '!'
	if b.Digest() != digest {
		t.Fatal("mutable plan view")
	}
	raw, e := b.Encode()
	if e != nil {
		t.Fatal(e)
	}
	restored, e := DecodeBlueprint(raw)
	if e != nil || restored.Digest() != digest {
		t.Fatal("snapshot", e)
	}
	if e = restored.ValidateCurrent(f.c, ctx); e != nil {
		t.Fatal(e)
	}
}

func TestBlueprintRejectsScopeCapabilityTrustAndNodeAdmissionChanges(t *testing.T) {
	f := makeFixture(t)
	c := smallCompose(t)
	for _, change := range []func(*PlanningContext){
		func(c *PlanningContext) { c.Tenant = "other" }, func(c *PlanningContext) { c.Project = "other" }, func(c *PlanningContext) { c.Features["inputs"] = false }, func(c *PlanningContext) { c.Features["volumes"] = false }, func(c *PlanningContext) { delete(c.Nodes, "node-b") }, func(c *PlanningContext) { n := c.Nodes["node-a"]; n.Draining = true; c.Nodes["node-a"] = n }, func(c *PlanningContext) { n := c.Nodes["node-b"]; n.Capacity.CPU = 1; c.Nodes["node-b"] = n },
	} {
		ctx := contextFor(t, f)
		change(&ctx)
		_, e := Compile(c, f.c, ctx)
		deny(t, e)
	}
	ctx := contextFor(t, f)
	c.Services["web"] = func() ComposeService {
		s := c.Services["web"]
		s.Image = "untrusted.invalid/team/app@sha256:" + strings.Repeat("b", 64)
		return s
	}()
	_, e := Compile(c, f.c, ctx)
	deny(t, e)
	c = smallCompose(t)
	tenant, _ := f.c.Tenant("tenant")
	policy, e := f.c.SetNodes("admin", "tenant", tenant.Revision, []string{"node-a"})
	if e != nil {
		t.Fatal(e)
	}
	_, e = Compile(c, policy, ctx)
	deny(t, e)
	c = frozenCompose(t)
	ctx.Project = c.Name
	ctx.Features["network-services"] = true
	ctx.Features["registry"] = true
	ctx.Features["git-cd"] = true
	n := ctx.Nodes["node-a"]
	n.Voter = false
	ctx.Nodes["node-a"] = n
	_, e = Compile(c, f.c, ctx)
	deny(t, e)
}

func TestBlueprintRejectsCIDRAddressAndWriterConflicts(t *testing.T) {
	f := makeFixture(t)
	base := smallCompose(t)
	for _, change := range []func(*Compose){
		func(c *Compose) {
			web := c.Services["web"]
			web.Sfc.Node = "node-b"
			web.Networks["app"] = Attachment{IPv4: "10.240.20.10"}
			c.Services["web"] = web
		},
		func(c *Compose) {
			web := c.Services["web"]
			web.Networks["app"] = Attachment{IPv4: "192.0.2.9"}
			c.Services["web"] = web
		},
		func(c *Compose) {
			web := c.Services["web"]
			web.Sfc.Node = "node-b"
			web.Networks["app"] = Attachment{IPv4: "10.240.20.11"}
			web.Volumes = Mounts{{Type: "volume", Source: "mysql-data", Target: "/data"}}
			c.Services["web"] = web
		},
		func(c *Compose) { v := c.Volumes["mysql-data"]; v.Sfc.Node = "node-a"; c.Volumes["mysql-data"] = v },
		func(c *Compose) { v := c.Volumes["mysql-data"]; v.Sfc.Quota = "hard"; c.Volumes["mysql-data"] = v },
	} {
		raw, _ := json.Marshal(base)
		var c Compose
		_ = json.Unmarshal(raw, &c)
		change(&c)
		_, e := Compile(c, f.c, contextFor(t, f))
		deny(t, e)
	}
	ctx := contextFor(t, f)
	var e error
	ctx.Networks, e = ctx.Networks.Create(f.c, "admin", ctx.Networks.Revision(), tenancy.Network{Tenant: "other", ID: "occupied", Node: "node-a", Owner: public(f.na), Pools: []tenancy.Subnet{{ID: "pool", Prefix: mustPrefix("10.240.10.0/25"), Gateway: mustAddr("10.240.10.1"), MTU: 1280}}})
	if e != nil {
		t.Fatal(e)
	}
	_, e = Compile(base, f.c, ctx)
	deny(t, e)
}

func TestBlueprintFeedsTheSameSecretVolumeConsumerCore(t *testing.T) {
	f := makeFixture(t)
	b, e := Compile(smallCompose(t), f.c, contextFor(t, f))
	if e != nil {
		t.Fatal(e)
	}
	web, e := b.Inputs("web", "web-task", 4, public(private(30)))
	if e != nil {
		t.Fatal(e)
	}
	db, e := b.Inputs("db", "db-task", 4, public(private(30)))
	if e != nil {
		t.Fatal(e)
	}
	f.approveAll(web, db)
	reserved := f.reserve(web, db)
	for i, n := range []Needs{web, db} {
		stage, e := reserved.Bindings[i].Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, f.values(n), 4096)
		if e != nil || len(stage.Files()) != 1 || string(stage.Files()[0].Data) != "private-db-value" {
			t.Fatal("same input core not consumed", e)
		}
	}
	if reserved.Bindings[1].Pins()[0].Scope.Generation != 8 {
		t.Fatal("planner assumed native generation one")
	}
}

func TestBlueprintStoredArtifactNeedsCurrentRevalidation(t *testing.T) {
	f := makeFixture(t)
	ctx := contextFor(t, f)
	b, e := Compile(smallCompose(t), f.c, ctx)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := b.Encode()
	for _, change := range []func(*blueprintRecord){
		func(d *blueprintRecord) { d.Schema = 2 }, func(d *blueprintRecord) { d.Steps[0].Dependencies = []Dependency{{d.Steps[0].Key, Applied}} }, func(d *blueprintRecord) { d.Steps[0].Owner = [32]byte{88} },
	} {
		var d blueprintRecord
		_ = json.Unmarshal(raw, &d)
		change(&d)
		bad, _ := json.Marshal(d)
		_, e = DecodeBlueprint(bad)
		deny(t, e)
	}
	// A structurally valid, attacker-edited goal is still not an authorized plan.
	var d blueprintRecord
	_ = json.Unmarshal(raw, &d)
	d.Steps[0].Goal = goal(map[string]string{"unexpected": "goal"})
	forged, _ := json.Marshal(d)
	read, e := DecodeBlueprint(forged)
	if e != nil {
		t.Fatal(e)
	}
	deny(t, read.ValidateCurrent(f.c, ctx))
	n := ctx.Nodes["node-b"]
	n.Revision++
	ctx.Nodes["node-b"] = n
	deny(t, b.ValidateCurrent(f.c, ctx))
}

func TestComposeKeepsImageTagsUnpinned(t *testing.T) {
	raw := strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64))
	raw = strings.Replace(raw, "docker.io/library/php@sha256:"+strings.Repeat("a", 64), "php:8.3-fpm", 1)
	c, err := ParseCompose([]byte(raw))
	if err != nil {
		t.Fatal("tag refused", err)
	}
	found := false
	for _, s := range c.Services {
		if s.Image == "docker.io/library/php:8.3-fpm" {
			found = true
		}
	}
	if !found {
		t.Fatal("tag not kept as a normalized tag reference")
	}
	bad := strings.Replace(raw, "php:8.3-fpm", "PHP:Bad Tag", 1)
	var ie *InputError
	if _, err = ParseCompose([]byte(bad)); !errors.As(err, &ie) || ie.Code != "INVALID_IMAGE" {
		t.Fatal("bad reference", err)
	}
}
