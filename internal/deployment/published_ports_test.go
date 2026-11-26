// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/workload"
	"gopkg.in/yaml.v3"
)

func TestComposePublishedPortsStandardFormsAndFrozenTaskRecipe(t *testing.T) {
	base := strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64))
	short := strings.Replace(base, "    command: [php, app.php]", "    ports: ['127.0.0.1:18080:8080/tcp', '[::1]:18081:8081/udp', '19000-19002:9000-9002', '20000-20010:9003', '9004']\n    command: [php, app.php]", 1)
	long := strings.Replace(base, "    command: [php, app.php]", `    ports:
      - {target: 8080, published: '18080', host_ip: 127.0.0.1, protocol: tcp}
      - {target: 8081, published: '18081', host_ip: '::1', protocol: udp}
      - {target: 9000, published: '19000'}
      - {target: 9001, published: '19001'}
      - {target: 9002, published: '19002'}
      - {target: 9003, published: '20000-20010'}
      - {target: 9004}
    command: [php, app.php]`, 1)
	a, err := ParseCompose([]byte(short))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseCompose([]byte(long))
	if err != nil || !slices.Equal(a.Services["web"].Ports, b.Services["web"].Ports) {
		t.Fatal("compose-go short/long meaning changed", a.Services["web"].Ports, b.Services["web"].Ports, err)
	}
	if len(a.Services["web"].Ports) != 7 {
		t.Fatal("paired range or dynamic target dropped", a.Services["web"].Ports)
	}
	raw, err := yaml.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ParseCompose(raw)
	if err != nil || !slices.Equal(restored.Services["web"].Ports, a.Services["web"].Ports) {
		t.Fatal("effective input not reproducible", err)
	}
	ports := a.Services["web"].Ports
	_, plan, material := taskMaterialFixtureWith(t, func(c *Compose) { s := c.Services["db"]; s.Ports = ports; c.Services["db"] = s })
	_, spec, err := plan.taskRecipe("db", material, material.Bridge.Owner)
	if err != nil || !slices.Equal(spec.Ports, ports) {
		t.Fatal("shared Task recipe dropped ports", err)
	}
	spec.Ports[0].Published = "1"
	original, _, _ := plan.TaskInput("db")
	if !slices.Equal(original.Ports, ports) {
		t.Fatal("native recipe mutated accepted definition")
	}
	encoded, err := plan.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBlueprint(encoded)
	if err != nil || decoded.Digest() != plan.Digest() {
		t.Fatal("frozen port intent changed", err)
	}
	noPorts := ComposeService{}
	legacy, _ := json.Marshal(noPorts)
	if bytes.Contains(legacy, []byte(`"Ports"`)) {
		t.Fatal("nil legacy service bytes changed")
	}
}

func TestStandalonePublishedPortsUseSameServiceDefinition(t *testing.T) {
	f, input, ctx, _ := externalFixture(t)
	input.Name = ""
	input.MyDC.Delivery = nil
	for name := range input.Services {
		if len(input.Services) > 1 {
			delete(input.Services, name)
		}
	}
	ports, _ := workload.NormalizePublishedPorts([]workload.PublishedPort{{Target: 8080, Published: "18080", HostIP: "127.0.0.1"}, {Target: 53, Published: "", Protocol: "udp"}})
	for name, s := range input.Services {
		s.DependsOn = nil
		s.MyDC.Nodes = nil
		s.MyDC.PerNode = 0
		s.Ports = ports
		input.Services[name] = s
	}
	raw, err := marshalApp(input)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Project = ""
	ctx.ExternalNetworks = nil
	b, err := CompileStandaloneDocument(raw, "published", f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	service, _, err := b.TaskInput("web")
	if err != nil || !slices.Equal(service.Ports, ports) {
		t.Fatal("standalone forked service publication", err)
	}
	encoded, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeBlueprint(encoded)
	if err != nil || restored.Digest() != b.Digest() || !bytes.Equal(restored.OriginalDocument().Body, raw) {
		t.Fatal("standalone source/target not frozen", err)
	}
}

func TestPublishedHostPortConflictsPreserveSourceAndDockerAllocation(t *testing.T) {
	owner := [32]byte{1}
	port := workload.PublishedPort{Target: 8080, Published: "18080", Protocol: "tcp"}
	original := HostPortUse{Key: "workload/task/tenant/app/web", Node: "a", Owner: owner, Ports: []workload.PublishedPort{port}}
	next := original
	next.Key = "workload/task/other/app/web"
	next.Ports = slices.Clone(original.Ports)
	next.Ports[0].HostIP = "127.0.0.1"
	if CheckHostPortUses([]HostPortUse{original}, next) == nil {
		t.Fatal("foreign tenant took wildcard listener")
	}
	if CheckHostPortUses([]HostPortUse{original}, original) != nil {
		t.Fatal("exact original replacement refused")
	}
	differentOwner := original
	differentOwner.Owner = [32]byte{2}
	if CheckHostPortUses([]HostPortUse{original}, differentOwner) == nil {
		t.Fatal("same key foreign owner took listener")
	}
	next.Node = "b"
	if CheckHostPortUses([]HostPortUse{original}, next) != nil {
		t.Fatal("other owner node conflated")
	}
	next.Node = "a"
	next.Ports[0].Protocol = "udp"
	if CheckHostPortUses([]HostPortUse{original}, next) != nil {
		t.Fatal("TCP/UDP conflated")
	}
	next.Ports[0].Protocol = "tcp"
	next.Ports[0].Published = "18080-18090"
	if CheckHostPortUses([]HostPortUse{original}, next) != nil {
		t.Fatal("whole selection range reserved")
	}
	next.Ports[0].Published = ""
	if CheckHostPortUses([]HostPortUse{original}, next) != nil {
		t.Fatal("dynamic request preallocated")
	}
	d := IngressDeclaration{Listeners: []ListenerDeclaration{{Address: "0.0.0.0:18080", HTTP3: true}}}
	ingress, err := IngressHostPortUse("ingress/tenant/app/http", "a", owner, d)
	if err != nil {
		t.Fatal(err)
	}
	next.Ports[0].Published = "18080"
	next.Ports[0].Protocol = "udp"
	if CheckHostPortUses([]HostPortUse{ingress}, next) == nil {
		t.Fatal("HTTP3 host socket not retained")
	}
	d.Listeners[0].HTTP3 = false
	ingress, _ = IngressHostPortUse("ingress/tenant/app/http", "a", owner, d)
	if CheckHostPortUses([]HostPortUse{ingress}, next) != nil {
		t.Fatal("HTTP-only listener blocked UDP")
	}
}
