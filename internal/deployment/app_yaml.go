// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"errors"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// The app.yaml forms of a few x-sfc values (devel/design/cli-and-formats.md,
// app.yaml). Only the yaml shape is written here: the Go fields and their
// JSON (plans, stored artifacts) stay the same.

var errAppYAML = errors.New("invalid app.yaml value")

// readyYAML is `ready: {http: PATH, port: N, timeout: D}`; the scalar
// `ready: healthcheck` is a Readiness of kind exec.
type readyYAML struct {
	HTTP    string `yaml:"http"`
	Port    uint16 `yaml:"port"`
	Timeout string `yaml:"timeout,omitempty"`
}

func (r *Readiness) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		if n.Value != "healthcheck" {
			return errAppYAML
		}
		*r = Readiness{Kind: "exec"}
		return nil
	}
	var v readyYAML
	if err := strictNode(n, &v); err != nil || v.HTTP == "" {
		return errAppYAML
	}
	*r = Readiness{Kind: "http", Path: v.HTTP, Port: v.Port, Timeout: v.Timeout}
	return nil
}

func (r Readiness) MarshalYAML() (any, error) {
	if r.Kind == "exec" {
		return "healthcheck", nil
	}
	return readyYAML{HTTP: r.Path, Port: r.Port, Timeout: r.Timeout}, nil
}

// SecretSources is `secrets.from: [NAME, group/NAME, cluster/NAME,
// cluster/group/NAME]`. Without "cluster/" the source is in the tenant.
type SecretSources []Selector

func (s *SecretSources) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return errAppYAML
	}
	out := SecretSources{}
	for _, item := range n.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return errAppYAML
		}
		sel, ok := parseSecretSource(item.Value)
		if !ok {
			return errAppYAML
		}
		out = append(out, sel)
	}
	*s = out
	return nil
}

func (s SecretSources) MarshalYAML() (any, error) {
	out := make([]string, len(s))
	for i, sel := range s {
		out[i] = sel.String()
	}
	return out, nil
}

func parseSecretSource(text string) (Selector, bool) {
	sel := Selector{Scope: "tenant"}
	if rest, ok := strings.CutPrefix(text, "cluster/"); ok {
		sel.Scope, text = "cluster", rest
	}
	if rest, ok := strings.CutPrefix(text, "group/"); ok {
		sel.Group = rest
	} else {
		sel.Secret = text
	}
	return sel, validSelector(sel)
}

// String is the app.yaml form of a secret source.
func (s Selector) String() string {
	text := s.Secret
	if s.Group != "" {
		text = "group/" + s.Group
	}
	if s.Scope == "cluster" {
		text = "cluster/" + text
	}
	return text
}

// VolumeSize is `size: 2GiB` (or a byte count). JSON keeps the number.
type VolumeSize uint64

func (v *VolumeSize) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return errAppYAML
	}
	if n.Tag == "!!int" {
		b, err := strconv.ParseUint(n.Value, 10, 64)
		if err != nil {
			return errAppYAML
		}
		*v = VolumeSize(b)
		return nil
	}
	b, err := byteSize(n.Value)
	if err != nil {
		return errAppYAML
	}
	*v = VolumeSize(b)
	return nil
}

func (v VolumeSize) MarshalYAML() (any, error) {
	for _, u := range []struct {
		suffix string
		shift  uint
	}{{"GiB", 30}, {"MiB", 20}, {"KiB", 10}} {
		if v != 0 && uint64(v)%(1<<u.shift) == 0 {
			return strconv.FormatUint(uint64(v)>>u.shift, 10) + u.suffix, nil
		}
	}
	return uint64(v), nil
}

// serviceSecretsYAML is a service's `x-sfc.secrets` block: `from` (secret
// sources whose keys become files), `env` (one key into an environment
// variable) and `socket` (sources served over sfev.sock).
type serviceSecretsYAML struct {
	From   SecretSources       `yaml:"from,omitempty"`
	Env    []SecretEnvironment `yaml:"env,omitempty"`
	Socket SecretSources       `yaml:"socket,omitempty"`
}

type serviceExtensionYAML struct {
	Nodes     []string            `yaml:"nodes,omitempty"`
	PerNode   uint32              `yaml:"per_node,omitempty"`
	Node      string              `yaml:"node,omitempty"`
	Readiness *Readiness          `yaml:"ready,omitempty"`
	Secrets   *serviceSecretsYAML `yaml:"secrets,omitempty"`
	Lifecycle *ServiceLifecycle   `yaml:"lifecycle,omitempty"`
	Logs      *LogsDeclaration    `yaml:"logs,omitempty"`
}

func (x *ServiceExtension) UnmarshalYAML(n *yaml.Node) error {
	var v serviceExtensionYAML
	if err := strictNode(n, &v); err != nil {
		return err
	}
	out := ServiceExtension{Nodes: v.Nodes, PerNode: v.PerNode, Node: v.Node, Readiness: v.Readiness, Lifecycle: v.Lifecycle, Logs: v.Logs}
	if s := v.Secrets; s != nil {
		out.Sources, out.SecretEnv, out.Socket = s.From, s.Env, s.Socket
	}
	*x = out
	return nil
}

func (x ServiceExtension) MarshalYAML() (any, error) {
	v := serviceExtensionYAML{Nodes: x.Nodes, PerNode: x.PerNode, Node: x.Node, Readiness: x.Readiness, Lifecycle: x.Lifecycle, Logs: x.Logs}
	if len(x.Sources) != 0 || len(x.SecretEnv) != 0 || len(x.Socket) != 0 {
		v.Secrets = &serviceSecretsYAML{From: x.Sources, Env: x.SecretEnv, Socket: x.Socket}
	}
	return v, nil
}
