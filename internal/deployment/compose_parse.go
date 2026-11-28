// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/workload"
	"gopkg.in/yaml.v3"
)

type InputError struct{ Code, Path string }

func (e *InputError) Error() string   { return e.Code + ": " + e.Path }
func inputError(code, p string) error { return &InputError{code, p} }

// strictNode preserves KnownFields inside the few Compose union forms.
func strictNode(n *yaml.Node, target any) error {
	raw, e := yaml.Marshal(n)
	if e != nil {
		return inputError("INVALID_FIELD", "value")
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if d.Decode(target) != nil {
		return inputError("INVALID_FIELD", "value")
	}
	return nil
}

// ParseCompose accepts declaration syntax, not deployed feature availability.
// Canonical is a metadata artifact; it must never be populated with fetched data.
func ParseCompose(raw []byte) (Compose, error) {
	return parseCompose(raw, false)
}

// ParseApp uses the same decoder/normalizer as persisted schema1 Compose
// artifacts, with the tenant app input boundary applied before normalization.
// ParseCompose remains the reader for already accepted, immutable old artifacts.
func ParseApp(raw []byte) (Compose, error) {
	return parseCompose(raw, true)
}

func ParseStandalone(raw []byte) (Compose, error) { return parseCompose(raw, true, true) }

func parseCompose(raw []byte, app bool, standalone ...bool) (Compose, error) {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return Compose{}, inputError("INPUT_BUDGET", "document")
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	var tree yaml.Node
	if d.Decode(&tree) != nil || d.Decode(new(any)) != io.EOF {
		return Compose{}, inputError("ONE_YAML_DOCUMENT_REQUIRED", "document")
	}
	remaining := 65536
	literalSources := lifecycleLiteralSources(&tree)
	var check func(*yaml.Node, int) error
	check = func(n *yaml.Node, depth int) error {
		remaining--
		if remaining < 0 || depth > 32 || n.Kind == yaml.AliasNode {
			return inputError("TREE_BUDGET_OR_ALIAS", "document")
		}
		if n.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || seen[k.Value] {
					return inputError("DUPLICATE_OR_NONSTRING_KEY", "document")
				}
				seen[k.Value] = true
			}
		}
		if n.Kind == yaml.ScalarNode && (strings.Contains(n.Value, "$") && !literalSources[n] || strings.ContainsRune(n.Value, 0)) {
			return inputError("INTERPOLATION_OR_NUL_FORBIDDEN", "document")
		}
		for _, child := range n.Content {
			if e := check(child, depth+1); e != nil {
				return e
			}
		}
		return nil
	}
	if e := check(&tree, 0); e != nil {
		return Compose{}, e
	}
	if len(tree.Content) != 1 || tree.Content[0].Kind != yaml.MappingNode {
		return Compose{}, inputError("APP_MAPPING_REQUIRED", "document")
	}
	root := tree.Content[0]

	if app {
		if err := appFields(root); err != nil {
			return Compose{}, err
		}
	}
	c, err := loadCompose(raw, root, len(standalone) == 1 && standalone[0])
	if err != nil {
		return c, err
	}
	if !app {
		_, _, err := c.LifecycleProgram()
		return c, err
	}
	for alias, n := range c.Networks {
		n.External = true // an omitted external flag still names an existing network
		c.Networks[alias] = n
	}
	if c.Standalone {
		return c, c.validateApp(true)
	}
	return c, c.ValidateApp()
}
func (c Compose) Canonical() ([]byte, error) {
	if e := c.validate(); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(c)
	if len(raw) > 4<<20 {
		return nil, inputError("INPUT_BUDGET", "canonical")
	}
	return raw, e
}
func (c Compose) Digest() ([32]byte, error) {
	raw, e := c.Canonical()
	if e != nil {
		return [32]byte{}, e
	}
	return sha256.Sum256(raw), nil
}

func nanoCPU(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	dots := 0
	for _, r := range s {
		if r == '.' {
			dots++
		} else if r < '0' || r > '9' {
			return 0, ErrInputs
		}
	}
	if dots > 1 {
		return 0, ErrInputs
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return 0, ErrInputs
	}
	r.Mul(r, big.NewRat(1e9, 1))
	if !r.IsInt() || !r.Num().IsUint64() || r.Sign() <= 0 || r.Num().Uint64() > math.MaxInt64 {
		return 0, ErrInputs
	}
	return r.Num().Uint64(), nil
}
func byteSize(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	s = strings.ToLower(s)
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, ErrInputs
	}
	n, e := strconv.ParseUint(s[:i], 10, 64)
	if e != nil {
		return 0, ErrInputs
	}
	multipliers := map[string]uint64{"": 1, "b": 1, "k": 1 << 10, "kb": 1 << 10, "kib": 1 << 10, "m": 1 << 20, "mb": 1 << 20, "mib": 1 << 20, "g": 1 << 30, "gb": 1 << 30, "gib": 1 << 30}
	m, ok := multipliers[s[i:]]
	if !ok || n == 0 || n > math.MaxInt64/m {
		return 0, ErrInputs
	}
	return n * m, nil
}
func absoluteTarget(s string) bool {
	return strings.HasPrefix(s, "/") && s != "/" && path.Clean(s) == s && !strings.ContainsAny(s, "\x00\r\n") && len(s) <= 256
}
func relativeFile(s string) bool {
	return s != "" && !path.IsAbs(s) && path.Clean(s) == s && s != ".." && !strings.HasPrefix(s, "../") && !strings.ContainsAny(s, "\\\x00\r\n") && len(s) <= 256
}
func validSelector(s Selector) bool {
	return (s.Secret != "") != (s.Group != "") && (s.Secret == "" || identifier(s.Secret)) && (s.Group == "" || identifier(s.Group)) && (s.Scope == "tenant" || s.Scope == "cluster")
}
func sortedStrings(v []string) []string { v = slices.Clone(v); slices.Sort(v); return v }
func (c *Compose) normalize() error {
	if c.Sfc.Schema == 0 {
		c.Sfc.Schema = 1
	}
	for name, s := range c.Services {
		// A tag stays a tag: it is resolved when a deployment creates its
		// containers, never pinned in the app definition.
		image, e := access.ParseImage(s.Image)
		if e != nil {
			return inputError("INVALID_IMAGE", "services."+name+".image")
		}
		s.Image = image.Reference
		if s.ReadOnly == nil {
			b := !c.Standalone
			s.ReadOnly = &b
		}
		if len(s.CapDrop) == 0 {
			s.CapDrop = []string{"ALL"}
		}
		if len(s.SecurityOpt) == 0 {
			s.SecurityOpt = []string{"no-new-privileges:true"}
		}
		s.CapDrop = sortedStrings(s.CapDrop)
		s.SecurityOpt = sortedStrings(s.SecurityOpt)
		cpu, e := nanoCPU(s.CPUs)
		if e != nil {
			return inputError("INVALID_CPU", "services."+name)
		}
		if cpu > 0 {
			s.CPUs = new(big.Rat).SetFrac(new(big.Int).SetUint64(cpu), big.NewInt(1e9)).FloatString(9)
			s.CPUs = strings.TrimRight(strings.TrimRight(s.CPUs, "0"), ".")
		}
		memory, e := byteSize(s.Memory)
		if e != nil {
			return inputError("INVALID_MEMORY", "services."+name)
		}
		if memory > 0 {
			s.Memory = strconv.FormatUint(memory, 10)
		}
		for dep, rule := range s.DependsOn {
			if rule.Condition == "" {
				rule.Condition = "service_started"
				s.DependsOn[dep] = rule
			}
		}
		for i, p := range s.Secrets {
			if p.Target == "" {
				p.Target = p.Source
			}
			if !strings.HasPrefix(p.Target, "/") {
				p.Target = "/run/secrets/" + p.Target
			}
			if p.UID == "" {
				p.UID = "10001"
			}
			if p.GID == "" {
				p.GID = "10001"
			}
			if p.Mode == "" {
				p.Mode = "0400"
			}
			s.Secrets[i] = p
		}
		for i, r := range s.Sfc.Sources {
			if r.Scope == "" {
				r.Scope = "tenant"
			}
			s.Sfc.Sources[i] = r
		}
		c.Services[name] = s
	}
	for name, v := range c.Volumes {
		if v.Sfc.Retain == nil {
			keep := true
			v.Sfc.Retain = &keep
		}
		if v.Sfc.Driver == "" {
			v.Sfc.Driver = "local"
		}
		if v.Sfc.Access == "" {
			v.Sfc.Access = "single-writer"
		}
		if v.Sfc.Quota == "" {
			v.Sfc.Quota = "observe"
		}
		c.Volumes[name] = v
	}
	for name, s := range c.Secrets {
		if s.File != "" && strings.HasPrefix(s.File, "./") {
			s.File = strings.TrimPrefix(s.File, "./")
		}
		if s.Sfc.Key == "" && (s.File != "" || s.External) {
			s.Sfc.Key = name
		}
		if s.File == "" && !s.External && s.Sfc.Source == "" {
			s.Sfc.Source = "service-final-keyset"
		}
		c.Secrets[name] = s
	}
	if v := c.Sfc.Vault; v != nil {
		normalizeEntries := func(in []Selector) []Selector {
			for i := range in {
				if in[i].Scope == "" {
					in[i].Scope = "tenant"
				}
			}
			return in
		}
		v.Tree.Root.Entries = normalizeEntries(v.Tree.Root.Entries)
		for name, g := range v.Tree.Groups {
			g.Entries = normalizeEntries(g.Entries)
			g.Services = sortedStrings(g.Services)
			v.Tree.Groups[name] = g
		}
		for name, s := range v.Tree.Secrets {
			s.Keys = sortedStrings(s.Keys)
			v.Tree.Secrets[name] = s
		}
	}
	if d := c.Sfc.Delivery; d != nil {
		if d.Sync.Mode == "" {
			d.Sync.Mode = "manual"
		}
		if d.Sync.Drift == "" {
			d.Sync.Drift = "report"
		}
		if d.Runtime.Mode == "" {
			d.Runtime.Mode = "require-explicit-override"
		}
		if d.Runtime.Expiry == "" {
			d.Runtime.Expiry = "manual-release"
		}
		if d.Poll == 0 {
			d.Poll = 60
		}
		if d.Limits.Fetch == 0 {
			d.Limits.Fetch = 30
		}
		if d.Limits.Bytes == 0 {
			d.Limits.Bytes = 4 << 20
		}
		if d.Limits.Queued == 0 {
			d.Limits.Queued = 1
		}
		if d.Limits.Active == 0 {
			d.Limits.Active = 1
		}
	}
	return c.validate()
}
func (c Compose) validate() error {
	if c.Sfc.Schema != 1 || c.Name != "" && !identifier(c.Name) || len(c.Services) == 0 && !c.allowEmpty() || len(c.Services) > 128 || len(c.Networks) > 128 || len(c.Volumes) > 128 || len(c.Secrets) > 256 || c.Sfc.Tenant != "" && !identifier(c.Sfc.Tenant) || c.Sfc.Deployment != "" && !identifier(c.Sfc.Deployment) {
		return inputError("INVALID_APP", "document")
	}
	if _, _, err := c.LifecycleProgram(); err != nil {
		return err
	}
	for name, s := range c.Services {
		if s.LifecycleSources != nil || s.LifecycleProgram != nil || s.Sfc.Instance != nil {
			return inputError("RESERVED_TASK_METADATA", name)
		}
		if err := validateServicePlacement(s); err != nil {
			return err
		}
		if len(s.Sfc.Socket) != 0 {
			return inputError("INVALID_FIELD", "services."+name+".x-sfc.secrets.socket") // sfev.sock is not served yet
		}
		p := "services." + name
		if workload.ValidatePublishedPorts(s.Ports) != nil {
			return inputError("INVALID_PUBLISHED_PORTS", p+".ports")
		}
		if s.Logging != nil && s.Logging.Validate() != nil {
			return inputError("INVALID_LOGGING_POLICY", p+".logging")
		}
		if _, err := engine.ParseStopPolicy(s.StopGracePeriod, s.StopSignal); err != nil {
			return inputError("INVALID_STOP_POLICY", p)
		}
		if !identifier(name) || s.Sfc.Node != "" && !identifier(s.Sfc.Node) || s.Standalone != c.Standalone || s.ReadOnly == nil || !c.Standalone && !*s.ReadOnly || !slices.Equal(s.CapDrop, []string{"ALL"}) || !slices.Equal(s.SecurityOpt, []string{"no-new-privileges:true"}) || len(s.WorkingDir) > 1024 || s.WorkingDir != "" && !strings.HasPrefix(s.WorkingDir, "/") || s.WorkingDir != "" && (path.Clean(s.WorkingDir) != s.WorkingDir || strings.ContainsAny(s.WorkingDir, "\x00\r\n")) || !c.Standalone && (s.TTY || s.StdinOpen) || len(s.Environment) > 128 || len(s.Networks) > 16 || len(s.Volumes) > 64 || len(s.Secrets)+len(s.Sfc.SecretEnv) > 256 {
			return inputError("INVALID_SERVICE", p)
		}
		if _, e := access.ParseImage(s.Image); e != nil {
			return inputError("INVALID_IMAGE", p)
		}
		if _, e := nanoCPU(s.CPUs); e != nil {
			return inputError("INVALID_CPU", p)
		}
		if m, e := byteSize(s.Memory); e != nil || m > 0 && m < 16<<20 {
			return inputError("INVALID_MEMORY", p)
		}
		for _, a := range []*Arguments{s.Command, s.Entrypoint} {
			if a != nil {
				if len(*a) > 128 {
					return inputError("COMMAND_BUDGET", p)
				}
				for _, v := range *a {
					if len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") {
						return inputError("INVALID_ARGUMENT", p)
					}
				}
			}
		}
		for k, v := range s.Environment {
			if !validKey(k) || len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") {
				return inputError("INVALID_ENVIRONMENT", p)
			}
		}
		if s.User != "" {
			parts := strings.Split(s.User, ":")
			if len(parts) != 2 {
				return inputError("NUMERIC_USER_REQUIRED", p)
			}
			for _, v := range parts {
				if n, e := strconv.ParseUint(v, 10, 32); e != nil || n == 0 {
					return inputError("NONROOT_USER_REQUIRED", p)
				}
			}
		}
		for dep, r := range s.DependsOn {
			d, ok := c.Services[dep]
			_, conditionErr := dependencyCondition(r.Condition)
			if !ok || dep == name || conditionErr != nil || r.Condition == "service_healthy" && !d.hasReadiness() {
				return inputError("INVALID_DEPENDENCY", p+".depends_on")
			}
		}
		for network, a := range s.Networks {
			if _, ok := c.Networks[network]; !ok {
				return inputError("NETWORK_BINDING_REQUIRED", p)
			}
			if len(a.Aliases) > 32 {
				return inputError("DNS_ALIAS_LIMIT", p)
			}
			seenAliases := map[string]bool{}
			for _, alias := range a.Aliases {
				name, err := services.Domain(alias)
				if err != nil || seenAliases[name] {
					return inputError("INVALID_DNS_ALIAS", p)
				}
				seenAliases[name] = true
			}
			for _, address := range []string{a.IPv4, a.IPv6} {
				if address != "" {
					ip, e := netip.ParseAddr(address)
					if e != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || ip.Zone() != "" {
						return inputError("INVALID_ADDRESS", p)
					}
				}
			}
			if a.IPv4 != "" {
				ip, _ := netip.ParseAddr(a.IPv4)
				if !ip.Is4() {
					return inputError("INVALID_ADDRESS", p)
				}
			}
			if a.IPv6 != "" {
				ip, _ := netip.ParseAddr(a.IPv6)
				if !ip.Is6() {
					return inputError("INVALID_ADDRESS", p)
				}
			}
		}
		var targets []string
		for _, m := range s.Volumes {
			if m.Type != "volume" || !identifier(m.Source) || !absoluteTarget(m.Target) {
				return inputError("NAMED_VOLUME_REQUIRED", p)
			}
			if _, ok := c.Volumes[m.Source]; !ok {
				return inputError("VOLUME_BINDING_REQUIRED", p)
			}
			targets = append(targets, m.Target)
		}
		for _, m := range s.Secrets {
			secret, ok := c.Secrets[m.Source]
			if !ok {
				return inputError("SECRET_BINDING_REQUIRED", p)
			}
			uid, e := strconv.ParseUint(m.UID, 10, 32)
			if e != nil {
				return inputError("INVALID_UID", p)
			}
			gid, e := strconv.ParseUint(m.GID, 10, 32)
			if e != nil {
				return inputError("INVALID_GID", p)
			}
			mode, e := strconv.ParseUint(m.Mode, 8, 32)
			if e != nil || !validProjection(Projection{Key: secret.Sfc.Key, Target: m.Target, UID: uint32(uid), GID: uint32(gid), Mode: uint32(mode)}) {
				return inputError("INVALID_SECRET_MOUNT", p)
			}
			targets = append(targets, m.Target)
		}

		envNames := map[string]bool{}
		for _, projection := range s.Sfc.SecretEnv {
			if !workload.SecretEnvironmentName(projection.Name) || envNames[projection.Name] {
				return inputError("INVALID_SECRET_ENV", p)
			}
			if _, exists := s.Environment[projection.Name]; exists {
				return inputError("SECRET_ENV_CONFLICT", p)
			}
			if secret, exists := c.Secrets[projection.Source]; !exists || !validKey(secret.Sfc.Key) {
				return inputError("SECRET_BINDING_REQUIRED", p)
			}
			envNames[projection.Name] = true
		}
		for _, tmpfs := range s.Tmpfs {
			mount, err := parseTmpfs(tmpfs)
			if err != nil {
				return inputError("INVALID_TMPFS", p)
			}
			targets = append(targets, mount.Target)
		}
		memory, _ := byteSize(s.Memory)
		if memory == 0 {
			memory = math.MaxInt64
		}
		if _, err := s.TmpfsMounts(int64(memory)); err != nil {
			return inputError("INVALID_TMPFS", p)
		}
		for i, a := range targets {
			for _, b := range targets[:i] {
				if a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") {
					return inputError("OVERLAPPING_MOUNT", p)
				}
			}
		}
		for _, r := range s.Sfc.Sources {
			if !validSelector(r) {
				return inputError("INVALID_SECRET_SOURCE", p)
			}
		}
		if h := s.Healthcheck; h != nil {
			if _, err := h.dockerConfig(); err != nil {
				return inputError("INVALID_HEALTHCHECK", p+".healthcheck")
			}
		}
		if r := s.Sfc.Readiness; r != nil && (r.Kind != "http" && r.Kind != "exec" || r.Kind == "http" && (r.Port == 0 || !strings.HasPrefix(r.Path, "/"))) {
			return inputError("INVALID_READINESS", p)
		}
		if r := s.Sfc.Readiness; r != nil {
			if r.Kind == "http" {
				if _, err := r.httpProbe(); err != nil {
					return inputError("INVALID_READINESS", p)
				}
			} else if r.Timeout != "" {
				return inputError("INVALID_READINESS", p)
			}
		}
		for _, ip := range s.DNS {
			if a, e := netip.ParseAddr(ip); e != nil || a.IsUnspecified() || a.IsMulticast() {
				return inputError("INVALID_DNS_SERVER", p)
			}
		}
	}
	for id, n := range c.Networks {
		if !identifier(id) || n.Driver != "" && n.Driver != "bridge" || n.Name != "" && !identifier(n.Name) || n.External && len(n.Sfc.Pools) != 0 || n.Sfc.MTU != 0 && (n.Sfc.MTU < 1280 || n.Sfc.MTU > 65535) {
			return inputError("INVALID_NETWORK", "networks."+id)
		}
		for node, p := range n.Sfc.Pools {
			prefix, e := netip.ParsePrefix(p.CIDR)
			gateway, ge := netip.ParseAddr(p.Gateway)
			if !identifier(node) || e != nil || ge != nil || prefix != prefix.Masked() || !prefix.Contains(gateway) || gateway == prefix.Addr() {
				return inputError("INVALID_POOL", "networks."+id)
			}
		}
	}
	for id, v := range c.Volumes {
		if !identifier(id) || v.Name != "" && !identifier(v.Name) || v.Driver != "" && v.Driver != "local" || v.Sfc.Driver != "local" || v.Sfc.Node != "" && !identifier(v.Sfc.Node) || v.Sfc.Access != "single-writer" || v.Sfc.Retain == nil || !*v.Sfc.Retain || v.Sfc.Quota != "observe" && v.Sfc.Quota != "hard" || v.Sfc.Capacity > 1<<40 {
			return inputError("INVALID_RETAINED_VOLUME", "volumes."+id)
		}
		if m := v.Sfc.Migration; m != nil && (m.Mode != "cold" || !m.Fence || !m.Retain) {
			return inputError("UNSAFE_MIGRATION", "volumes."+id)
		}
	}
	for id, s := range c.Secrets {
		if !identifier(id) || s.Name != "" && !identifier(s.Name) || s.File != "" && !relativeFile(s.File) || s.File != "" && s.Sfc.Source != "" || s.File == "" && s.Sfc.Source != "service-final-keyset" && !s.External || s.Sfc.Key != "" && !validKey(s.Sfc.Key) {
			return inputError("INVALID_SECRET_REFERENCE", "secrets."+id)
		}
		if s.File != "" && s.Sfc.Key == "" {
			return inputError("SECRET_PROJECTION_KEY_REQUIRED", "secrets."+id)
		}
	}
	for id, s := range c.Services {
		for _, search := range s.DNSSearch {
			if !domain(search) {
				return inputError("INVALID_DNS_SEARCH", "services."+id)
			}
		}
		if s.Sfc.Readiness != nil && s.Sfc.Readiness.Kind == "exec" && (s.Healthcheck == nil || s.Healthcheck.disabled()) {
			return inputError("EXEC_HEALTHCHECK_REQUIRED", "services."+id)
		}
	}
	if c.Sfc.Routing != nil && c.Sfc.Routing.Default != "deny" {
		return inputError("CROSS_TENANT_DEFAULT_DENY_REQUIRED", "x-sfc.routing")
	}
	for id, r := range c.Sfc.Registries {
		if !identifier(id) || r.Trusted {
			return inputError("REGISTRY_IS_NOT_AUTO_TRUSTED", "x-sfc.registries")
		}
	}
	if e := c.validateExtensions(); e != nil {
		return e
	}
	if _, e := serviceOrder(c.Services); e != nil {
		return e
	}
	return nil
}

func (c Compose) allowEmpty() bool {
	return c.Services != nil && len(c.Services) == 0 && c.Sfc.Delivery != nil && c.Sfc.Delivery.Sync.AllowEmpty
}

func domain(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func (c Compose) validateExtensions() error {
	for id, h := range c.Sfc.Nodes {
		if !identifier(id) {
			return inputError("INVALID_NODE_HINT", "x-sfc.nodes")
		}
		if a, e := netip.ParseAddr(h.Underlay); e != nil || a.IsUnspecified() || a.IsMulticast() || a.Zone() != "" {
			return inputError("INVALID_NODE_HINT", "x-sfc.nodes")
		}
	}
	for id, n := range c.Networks {
		p := "networks." + id
		if r := n.Sfc.RuntimeChanges; r != nil && (r.Authority != "authenticated-sfcp-raft-cas" || r.Restart || r.Strategy != "staged" || r.Deadlines != "preserve" || r.Disruptive != "explicit-transition-plan") {
			return inputError("UNSAFE_RUNTIME_POLICY", p)
		}
		for node, a := range n.Sfc.TunnelAddresses {
			if !identifier(node) {
				return inputError("INVALID_TUNNEL_ADDRESS", p)
			}
			if prefix, e := netip.ParsePrefix(a); e != nil || prefix.Bits() != prefix.Addr().BitLen() || prefix.Addr().IsMulticast() || prefix.Addr().IsUnspecified() {
				return inputError("INVALID_TUNNEL_ADDRESS", p)
			}
		}
		for _, pool := range n.Sfc.Pools {
			prefix, _ := netip.ParsePrefix(pool.CIDR)
			if a := pool.AddressPlan; a != nil {
				docker, e := netip.ParsePrefix(a.DockerRange)
				first, fe := netip.ParseAddr(a.StaticFirst)
				last, le := netip.ParseAddr(a.StaticLast)
				if e != nil || fe != nil || le != nil || docker != docker.Masked() || !prefix.Contains(docker.Addr()) || docker.Bits() < prefix.Bits() || !docker.Contains(first) || !docker.Contains(last) || first.Compare(last) > 0 {
					return inputError("OVERLAPPING_ADDRESS_PLAN", p)
				}
			}
		}
		if d := n.Sfc.DNS; d != nil && d.Enabled {
			if !domain(d.Zone) || d.TTL == 0 || d.TTL > 3600 || d.NegativeTTL == 0 || d.NegativeTTL > d.TTL || !slices.Equal(sortedStrings(d.Transports), []string{"tcp", "udp"}) || d.Limits.Cache < 0 || d.Limits.Cache > 4096 || d.Limits.Inflight < 1 || d.Limits.Inflight > 4096 || d.Limits.TCP < 1 || d.Limits.TCP > 4096 || d.Limits.Timeout < 1 || d.Limits.Timeout > 60000 {
				return inputError("INVALID_DNS_POLICY", p)
			}
			if d.Reverse {
				for _, pool := range n.Sfc.Pools {
					prefix, e := netip.ParsePrefix(pool.CIDR)
					if e != nil {
						return inputError("INVALID_DNS_REVERSE_PREFIX", p)
					}
					if _, e = services.DNSReverseZone(prefix); e != nil {
						return inputError("INVALID_DNS_REVERSE_PREFIX", p)
					}
				}
			}
		}
	}
	if v := c.Sfc.Vault; v != nil {
		if v.Mode != "groups" && v.Mode != "local-file" {
			return inputError("INVALID_VAULT_MODE", "x-sfc.vault")
		}
		if v.Mode == "groups" && (v.Approval.Prompt != "once-per-required-group-without-valid-approval" || v.Approval.Reuse != "same-deployment-and-valid-group-scope" || !slices.Equal(v.Approval.Payload, []string{"approved_at", "fact", "target"})) {
			return inputError("INVALID_APPROVAL_POLICY", "x-sfc.vault")
		}
		if e := validateVaultTree(v); e != nil {
			return e
		}
		ids := map[string]bool{}
		for name, g := range v.Tree.Groups {
			if !identifier(name) || !identifier(g.ID) || ids[g.ID] || g.Parent != "tenant" && !identifier(g.Parent) {
				return inputError("INVALID_GROUP", "x-sfc.vault")
			}
			ids[g.ID] = true
		}
		for name, s := range v.Tree.Secrets {
			if !identifier(name) || !identifier(s.ID) || ids[s.ID] || s.Revision == 0 || !identifier(s.Profile) || !relativeFile(s.Object) || len(s.Keys) == 0 || len(s.Keys) > 256 {
				return inputError("INVALID_SECRET", "x-sfc.vault")
			}
			ids[s.ID] = true
			seen := map[string]bool{}
			for _, key := range s.Keys {
				if !validKey(key) || seen[key] {
					return inputError("INVALID_SECRET_KEY", "x-sfc.vault")
				}
				seen[key] = true
			}
		}
	}
	if i := c.Sfc.Ingress; i != nil {
		if err := validateIngressDeclaration(c, *i); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, l := range i.Listeners {
			if l.Shared != "" {
				if !identifier(l.Shared) || l.Address != "" || l.TLS || l.HTTP3 || seen["shared:"+l.Shared] {
					return inputError("INVALID_LISTENER", "x-sfc.ingress")
				}
				seen["shared:"+l.Shared] = true
				continue
			}
			if a, e := netip.ParseAddrPort(l.Address); e != nil || a.Port() == 0 || a.Addr().IsMulticast() || seen[l.Address] || l.HTTP3 && !l.TLS {
				return inputError("INVALID_LISTENER", "x-sfc.ingress")
			}
			seen[l.Address] = true
		}
	}
	if d := c.Sfc.Delivery; d != nil {
		if d.Sync.Mode != "manual" && d.Sync.Mode != "automatic" || d.Sync.Drift != "report" && d.Sync.Drift != "reconcile" || d.Runtime.Mode != "require-explicit-override" || d.Runtime.Expiry != "manual-release" || d.Poll < 1 || d.Poll > 86400 || d.Limits.Fetch < 1 || d.Limits.Fetch > 300 || d.Limits.Bytes < 1 || d.Limits.Bytes > 4<<20 || d.Limits.Queued != 1 || d.Limits.Active != 1 {
			return inputError("INVALID_CD_POLICY", "x-sfc.delivery")
		}
		if d.Enabled {
			u, e := url.Parse(d.Source.Repository)
			if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(d.Source.Repository, "\x00\r\n") || d.Source.Kind != "git" || d.Source.Ref == "" || len(d.Source.Ref) > 256 || !relativeFile(d.Source.Path) || d.Source.Credential != "" && !identifier(d.Source.Credential) {
				return inputError("INVALID_GIT_SOURCE", "x-sfc.delivery")
			}
		}
	}
	for id, r := range c.Sfc.Registries {
		if r.Enabled {
			if !identifier(r.Node) || r.Port == 0 || !domain(r.Listener.Host) || !identifier(r.Listener.Certificate) || r.Auth.Mode != "tenant-token" || r.Auth.Issuer != "builtin" || r.Auth.Anonymous || r.Auth.MaxToken == 0 || r.Auth.MaxToken > 300 {
				return inputError("INVALID_REGISTRY", "x-sfc.registries."+id)
			}
			if _, e := access.PinImage(r.Image); e != nil {
				return inputError("PINNED_IMAGE_REQUIRED", "x-sfc.registries."+id)
			}
			if _, e := netip.ParseAddrPort(r.Listener.Address); e != nil {
				return inputError("INVALID_REGISTRY_LISTENER", "x-sfc.registries."+id)
			}
		}
	}
	return nil
}

func serviceOrder(services map[string]ComposeService) ([]string, error) {
	var order []string
	seen := map[string]uint8{}
	var visit func(string) error
	visit = func(id string) error {
		if seen[id] == 1 {
			return inputError("DEPENDENCY_CYCLE", "services")
		}
		if seen[id] == 2 {
			return nil
		}
		s, ok := services[id]
		if !ok {
			return inputError("MISSING_DEPENDENCY", "services")
		}
		seen[id] = 1
		deps := make([]string, 0, len(s.DependsOn))
		for dep := range s.DependsOn {
			deps = append(deps, dep)
		}
		slices.Sort(deps)
		for _, dep := range deps {
			if e := visit(dep); e != nil {
				return e
			}
		}
		seen[id] = 2
		order = append(order, id)
		return nil
	}
	ids := make([]string, 0, len(services))
	for id := range services {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if e := visit(id); e != nil {
			return nil, e
		}
	}
	return order, nil
}

func (c Compose) String() string {
	digest, e := c.Digest()
	if e != nil {
		return "[invalid compose metadata]"
	}
	return fmt.Sprintf("[compose metadata %x]", digest[:8])
}

func validateVaultTree(v *VaultDeclaration) error {
	parents := map[string]string{}
	claimed := map[string]bool{}
	for name, g := range v.Tree.Groups {
		parents["group/"+name] = g.Parent
	}
	for name, s := range v.Tree.Secrets {
		parents["secret/"+name] = s.Parent
	}
	entries := func(parent string, items []Selector) error {
		for _, s := range items {
			if !validSelector(s) || s.Scope != "tenant" {
				return inputError("INVALID_GROUP_ENTRY", "x-sfc.vault")
			}
			k := "secret/" + s.Secret
			if s.Group != "" {
				k = "group/" + s.Group
			}
			if p, ok := parents[k]; !ok || p != parent || claimed[k] {
				return inputError("GROUP_PARENT_OR_ORDER_CONFLICT", "x-sfc.vault")
			}
			claimed[k] = true
		}
		return nil
	}
	if e := entries("tenant", v.Tree.Root.Entries); e != nil {
		return e
	}
	for name, g := range v.Tree.Groups {
		if e := entries(name, g.Entries); e != nil {
			return e
		}
	}
	if len(claimed) != len(parents) {
		return inputError("MISSING_GROUP_ENTRY", "x-sfc.vault")
	}
	for name, g := range v.Tree.Groups {
		seen := map[string]bool{name: true}
		parent := g.Parent
		for depth := 0; parent != "tenant"; depth++ {
			p, ok := v.Tree.Groups[parent]
			if !ok || seen[parent] || depth >= 31 {
				return inputError("GROUP_CYCLE_OR_DEPTH", "x-sfc.vault")
			}
			seen[parent] = true
			parent = p.Parent
		}
	}
	return nil
}
