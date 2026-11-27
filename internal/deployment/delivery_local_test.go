// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"net/netip"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func localServiceBody(t *testing.T, d Delivery) []byte {
	t.Helper()
	input, err := artifactCompose(d.d.Candidate.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	service := input.Services["web"]
	service.DependsOn = nil
	service.Volumes, service.Secrets = nil, nil
	service.Sfc.Sources, service.Sfc.SecretEnv, service.Sfc.Lifecycle = nil, nil, nil
	for name, attachment := range service.Networks {
		if attachment.IPv4 != "" {
			ip := netip.MustParseAddr(attachment.IPv4)
			for i := 0; i < 20; i++ {
				ip = ip.Next()
			}
			attachment.IPv4 = ip.String()
		}
		attachment.Aliases = nil
		service.Networks[name] = attachment
	}
	scope := d.Inventory().Scope()
	local := Compose{Name: scope.App, Sfc: AppExtension{Schema: 1, Tenant: scope.Tenant, Deployment: scope.Deployment}, Services: map[string]ComposeService{"worker": service}, Networks: input.Networks}
	raw, err := yaml.Marshal(local)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCDLocalServicesKeepOriginalGitRunningAndOwnSnapshot(t *testing.T) {
	f, ctx, d, _ := completedRegisteredApp(t)
	running := bytes.Clone(goal(d.d.Running))
	git := bytes.Clone(d.d.Candidate.Artifact.Body)
	input := localServiceBody(t, d)
	n, err := d.PutLocalServices(d.Revision(), 0, f.c, ctx, "alice", input)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.d.Candidate.Plan.Input.Services) != len(d.d.Candidate.Plan.Input.Services)+1 || !bytes.Equal(running, goal(n.d.Running)) || !bytes.Equal(git, n.d.Candidate.Artifact.Body) || n.LocalRevision() != 1 {
		t.Fatal("local addition changed original source or execution")
	}
	snapshot, err := n.Encode()
	if err != nil {
		t.Fatal(err)
	}
	n, err = DecodeDelivery(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	local := n.LocalServices()
	if local == nil || local.Digest != sha256.Sum256(input) || !bytes.Equal(local.Body, input) {
		t.Fatal("local source lost at checkpoint")
	}
	local.Body[0] = '!'
	if !bytes.Equal(n.LocalServices().Body, input) {
		t.Fatal("public local source aliases private bytes")
	}
	if _, err = n.PutLocalServices(n.Revision(), 0, f.c, ctx, "alice", nil); err == nil {
		t.Fatal("local source revision ignored")
	}
	cleared, err := n.PutLocalServices(n.Revision(), n.LocalRevision(), f.c, ctx, "alice", nil)
	if err != nil || cleared.LocalServices() != nil || cleared.LocalRevision() != 2 || len(cleared.d.Candidate.Plan.Input.Services) != len(d.d.Candidate.Plan.Input.Services) || !bytes.Equal(running, goal(cleared.d.Running)) {
		t.Fatal("clearing metadata stopped original tasks or lost source", err)
	}
}

func TestCDLocalServicesRejectGitNameChangesDependenciesAndManagementRoots(t *testing.T) {
	_, _, d, _ := completedRegisteredApp(t)
	body := localServiceBody(t, d)
	source, err := artifactCompose(d.d.Candidate.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*Compose){
		func(c *Compose) { c.Services["web"] = c.Services["worker"]; delete(c.Services, "worker") },
		func(c *Compose) {
			s := c.Services["worker"]
			s.DependsOn = Dependencies{"web": {Condition: "service_started"}}
			c.Services["worker"] = s
		},
		func(c *Compose) { c.Sfc.Delivery = source.Sfc.Delivery },
		func(c *Compose) {
			for alias, n := range c.Networks {
				n.Name = "other-managed-network"
				c.Networks[alias] = n
				break
			}
		},
	} {
		c, err := ParseApp(body)
		if err != nil {
			t.Fatal(err)
		}
		alter(&c)
		raw, _ := yaml.Marshal(c)
		local := &LocalServicesDocument{Revision: 1, Actor: "alice", Body: raw, Digest: sha256.Sum256(raw)}
		if _, err = mergeLocalServices(source, local, d.Inventory().Scope()); err == nil {
			t.Fatal("local fragment changed Git/management/dependency scope")
		}
	}
}

func TestCDGitLocalNameConflictIsExplicitAndCannotStartAnotherSync(t *testing.T) {
	f, ctx, d, _ := completedRegisteredApp(t)
	local := localServiceBody(t, d)
	n, err := d.PutLocalServices(d.Revision(), 0, f.c, ctx, "alice", local)
	if err != nil {
		t.Fatal(err)
	}
	source, err := artifactCompose(n.d.Candidate.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	addition, err := ParseApp(local)
	if err != nil {
		t.Fatal(err)
	}
	source.Services["worker"] = addition.Services["worker"]
	body, _ := yaml.Marshal(source)
	n, ticket, err := n.Fetch(n.Revision(), f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	input, err := RestoreFetchedDeliveryInput(ticket, strings.Repeat("d", 40), n.Policy().Source.Path, body, ArtifactMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	oldCandidate, _ := n.Candidate()
	oldRunning := bytes.Clone(goal(n.d.Running))
	blocked, err := n.Received(n.Revision(), f.c, ctx, input)
	if err != nil || blocked.SourceError() != "name-conflict" {
		t.Fatal("source conflict was not retained explicitly", err)
	}
	current, _ := blocked.Candidate()
	if current != oldCandidate || !bytes.Equal(oldRunning, goal(blocked.d.Running)) {
		t.Fatal("conflicting source replaced accepted inputs")
	}
	if _, err = blocked.Start(blocked.Revision(), f.c, ctx, "must-not-start", "user/original", 1); err == nil {
		t.Fatal("conflict allowed sync")
	}
}
