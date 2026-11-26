// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"testing"
)

func TestStandaloneUsesOriginalServiceCompilerAndOwnStableNamespace(t *testing.T) {
	f, input, ctx, _ := externalFixture(t)
	input.Name = ""
	input.MyDC.Delivery = nil
	for name := range input.Services {
		if len(input.Services) > 1 {
			delete(input.Services, name)
		}
	}
	for name, service := range input.Services {
		service.DependsOn = nil
		service.MyDC.Nodes = nil
		service.MyDC.PerNode = 0
		input.Services[name] = service
	}
	raw, err := marshalApp(input)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Project = ""
	// Named references use the same committed-source discovery as app.yaml.
	ctx.ExternalNetworks = nil
	b, err := CompileStandaloneDocument(raw, "debug", f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b.Scope().App != StandaloneScopeName(ctx.Tenant, "debug") || b.StandaloneName() != "debug" || b.OriginalDocument() == nil || !bytes.Equal(b.OriginalDocument().Body, raw) {
		t.Fatal("lost public source or owner kind")
	}
	service, _, err := b.TaskInput("web")
	if err != nil || len(service.Networks["app"].Aliases) != 0 {
		t.Fatal("omitted alias introduced a managed DNS requirement", service, err)
	}
	encoded, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeBlueprint(encoded)
	if err != nil || restored.Digest() != b.Digest() {
		t.Fatal("original standalone plan did not roundtrip", err)
	}
	if restored.CheckStandaloneInput() != nil || restored.CheckAppInput() == nil {
		t.Fatal("standalone forked the app service validation")
	}
	if StandaloneScopeName("tenant", "debug") == StandaloneScopeName("other", "debug") || StandaloneScopeName("tenant", "debug") == StandaloneScopeName("tenant", "other") {
		t.Fatal("internal owner namespace collided")
	}
}

func TestStandaloneRejectsAppOrReplicaCoupling(t *testing.T) {
	f, input, ctx, _ := externalFixture(t)
	input.Name = ""
	input.MyDC.Delivery = nil
	for name := range input.Services {
		if len(input.Services) > 1 {
			delete(input.Services, name)
		}
	}
	for name, service := range input.Services {
		service.DependsOn = nil
		input.Services[name] = service
	}
	for _, mutate := range []func(*Compose){func(c *Compose) {
		for name, s := range c.Services {
			s.DependsOn = Dependencies{"other": {Condition: "service_started"}}
			c.Services[name] = s
		}
	}, func(c *Compose) {
		for name, s := range c.Services {
			s.MyDC.Nodes = []string{"node"}
			s.MyDC.PerNode = 1
			c.Services[name] = s
		}
	}, func(c *Compose) {
		for _, s := range c.Services {
			c.Services["second"] = s
			break
		}
	}} {
		raw, _ := marshalApp(input)
		copy, err := ParseApp(raw)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&copy)
		raw, err = marshalApp(copy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = CompileStandaloneDocument(raw, "debug", f.c, ctx); err == nil {
			t.Fatal("coupled app accepted as standalone")
		}
	}
}
