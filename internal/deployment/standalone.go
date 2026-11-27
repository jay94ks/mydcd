// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/jay94ks/seafield/internal/access"
)

// StandaloneScopeName is an internal workload identity, not the public name.
// The explicit owner kind on the control record separates this namespace from
// apps; a colliding ordinary app must be rejected, never adopted.
func StandaloneScopeName(tenant, name string) string {
	if !identifier(tenant) || !identifier(name) {
		return ""
	}
	d := sha256.Sum256([]byte("sfc-standalone-scope-1\x00" + tenant + "\x00" + name))
	return "standalone-" + hex.EncodeToString(d[:24])
}

func validateStandaloneInput(c Compose, name string) error {
	if !identifier(name) || c.Name != "" && c.Name != name || len(c.Services) != 1 || c.Sfc.Delivery != nil {
		return inputError("STANDALONE_SINGLE_SERVICE_REQUIRED", "services")
	}
	for id, s := range c.Services {
		if len(s.DependsOn) != 0 || len(s.Sfc.Nodes) != 0 || s.Sfc.PerNode != 0 || s.Sfc.Instance != nil {
			return inputError("STANDALONE_SERVICE_REFERENCE", "services."+id)
		}
	}
	return c.validateApp(true)
}

// CompileStandaloneDocument reuses the exact service parser and app compiler.
// Owner/lifetime metadata is separate from this immutable workload definition,
// so a pin/name change cannot recreate a Task or its writable container layer.
func CompileStandaloneDocument(raw []byte, name string, policy access.Catalog, ctx PlanningContext, modes ...string) (Blueprint, error) {
	c, err := ParseStandalone(raw)
	if err != nil {
		return Blueprint{}, err
	}
	if err = validateStandaloneInput(c, name); err != nil {
		return Blueprint{}, err
	}
	if ctx.Project == "" {
		ctx.Project = StandaloneScopeName(ctx.Tenant, name)
	}
	if ctx.Project == "" {
		return Blueprint{}, ErrInputs
	}
	mode := "entrypoint"
	if len(modes) > 1 {
		return Blueprint{}, ErrInputs
	}
	if len(modes) == 1 && modes[0] != "" {
		mode = modes[0]
	}
	if mode != "entrypoint" && mode != "shell" {
		return Blueprint{}, ErrInputs
	}
	applyStandaloneMode(&c, mode)
	c.Name = ctx.Project
	b, err := compile(c, policy, ctx, nil, "standalone")
	if err != nil {
		return Blueprint{}, err
	}
	b.d.Document = &AppDocument{Body: bytes.Clone(raw), DefaultNode: ctx.DefaultNode, StandaloneName: name, StandaloneScope: ctx.Project, StandaloneMode: mode}
	if _, err = b.Encode(); err != nil {
		return Blueprint{}, err
	}
	return b, nil
}

func (b Blueprint) StandaloneName() string {
	if b.d.Document == nil {
		return ""
	}
	return b.d.Document.StandaloneName
}

func (b Blueprint) CheckStandaloneInput() error {
	if b.d.InputKind != "standalone" || b.StandaloneName() == "" {
		return ErrInputs
	}
	return b.d.Input.validateApp(true)
}

func applyStandaloneMode(c *Compose, mode string) {
	if mode != "shell" {
		return
	}
	for key, s := range c.Services {
		if s.Command == nil {
			a := Arguments{"/bin/sh"}
			s.Command = &a
		}
		if s.Entrypoint == nil {
			a := Arguments{}
			s.Entrypoint = &a
		}
		s.TTY, s.StdinOpen = true, true
		c.Services[key] = s
	}
}
