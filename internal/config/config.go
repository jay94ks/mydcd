// SPDX-License-Identifier: Apache-2.0

// Package config loads installation-local files without opening runtime resources.
package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/clusterapp"
	"github.com/jay94ks/seafield/internal/engineimage"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/ingress"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Peer struct {
	ID       string `yaml:"id"`
	Key      string `yaml:"key"`
	Endpoint string `yaml:"endpoint"`
	Voter    bool   `yaml:"voter"`
}

// Common is derived from the node's installation record (bootstrap.Effective),
// never read from YAML: a node learns its cluster, admin and peers from init or
// join.
type Common struct {
	Cluster string
	Admin   string
	Peers   []Peer
}

type Module struct {
	Enabled bool
	Body    yaml.Node
}
type NetworkLocal struct {
	Enabled bool `yaml:"enabled"`
}
type WorkloadLocal struct {
	Enabled bool `yaml:"enabled"`
}

// IngressLocal is node.yaml modules.ingress. TLS certificates come from the
// cluster certificate store, never from local files.
type IngressLocal struct {
	Enabled  bool                         `yaml:"enabled"`
	Gateways ingress.GatewayConfiguration `yaml:"gateways,omitempty"`
}

func (m Module) Decode(target any) error {
	b, err := yaml.Marshal(&m.Body)
	if err != nil {
		return err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	return d.Decode(target)
}

// has reports whether the module body sets key.
func (m Module) has(key string) bool {
	for i := 0; i+1 < len(m.Body.Content); i += 2 {
		if m.Body.Content[i].Value == key {
			return true
		}
	}
	return false
}

func (m *Module) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return errors.New("module must be a mapping")
	}
	found := false
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == "enabled" {
			v := n.Content[i+1]
			if v.Tag != "!!bool" {
				return errors.New("enabled must be boolean")
			}
			if err := v.Decode(&m.Enabled); err != nil {
				return err
			}
			found = true
		}
	}
	if !found {
		return errors.New("module requires enabled")
	}
	m.Body = *n
	return nil
}

type Node struct {
	Version int    `yaml:"version"`
	Common  Common `yaml:"-"`
	Node    struct {
		ID               string `yaml:"id"`
		StateDir         string `yaml:"state_dir"`
		IdentityDir      string `yaml:"identity_dir"`
		Listen           string `yaml:"listen"`
		ManagementSocket string `yaml:"management_socket,omitempty"`
		// InboundOnly: this node never dials other nodes; it uses the
		// sessions they open to it (a public node in front of servers
		// behind NAT, such as an ingress gateway).
		InboundOnly bool `yaml:"inbound_only,omitempty"`
	} `yaml:"node"`
	Modules        map[string]Module  `yaml:"modules"`
	Credentials    *CredentialBackend `yaml:"credentials,omitempty" json:",omitempty"`
	Vaults         []VaultBackend     `yaml:"vaults,omitempty" json:",omitempty"`
	ServiceCAs     []ServiceCA        `yaml:"service_cas,omitempty" json:",omitempty"`
	GitCredentials []GitCredential    `yaml:"git_credentials,omitempty" json:",omitempty"`
	ClusterApps    ClusterApps        `yaml:"cluster_apps,omitempty" json:",omitempty"`
	NodeShell      NodeShell          `yaml:"node_shell,omitempty" json:",omitempty"`
	Engine         Engine             `yaml:"engine,omitempty" json:",omitempty"`
	Firewall       NodeFirewall       `yaml:"firewall,omitempty" json:",omitempty"`

	// EngineAPI and EngineSocket are not node.yaml settings: a server's
	// engine always serves its API at DefaultEngineAPI and dials sfcd at
	// sfcp.DefaultEngineSocket. Tests and development runs set them (sfcd
	// --engine-api, --engine-socket) to run several nodes on one host.
	EngineAPI    string `yaml:"-" json:"-"`
	EngineSocket string `yaml:"-" json:"-"`
	// AnonymousImages is not a node.yaml setting either: tests set it so an
	// image pull with no registry login reads a fake source instead of the
	// image's registry over HTTPS. A server leaves it nil.
	AnonymousImages func(authority string) (engineimage.Opener, error) `yaml:"-" json:"-"`
}

// DefaultEngineAPI is the Seafield engine's (sfed) Engine API socket.
const DefaultEngineAPI = "unix:///run/sfe/sfed.sock"

// EngineEndpoint is the engine API this node uses: EngineAPI, or
// DefaultEngineAPI when it is empty.
func (c Node) EngineEndpoint() string {
	if c.EngineAPI != "" {
		return c.EngineAPI
	}
	return DefaultEngineAPI
}

// NodeFirewall is node.yaml firewall: whether sfcd may control this
// server's inbound firewall (devel/proposals/node-firewall.md). Off, sfcd
// leaves iptables alone. KeepOpen lists "tcp/PORT" or "udp/PORT" entries
// that stay open whatever rules are set remotely; nil keeps tcp/22, an
// explicit empty list keeps none.
type NodeFirewall struct {
	Managed  bool      `yaml:"managed,omitempty" json:",omitempty"`
	KeepOpen *[]string `yaml:"keep_open,omitempty" json:",omitempty"`
}

// DefaultKeepOpen is what keep_open holds when node.yaml leaves it out.
var DefaultKeepOpen = []string{"tcp/22"}

// KeepOpenPorts reads keep_open into protocol and port pairs.
func (f NodeFirewall) KeepOpenPorts() ([]KeepOpenPort, error) {
	list := DefaultKeepOpen
	if f.KeepOpen != nil {
		list = *f.KeepOpen
	}
	if len(list) > 32 {
		return nil, errors.New("firewall.keep_open holds at most 32 entries")
	}
	out := []KeepOpenPort{}
	for _, e := range list {
		k, ok := parseKeepOpen(e)
		if !ok {
			return nil, fmt.Errorf("firewall.keep_open entry %q must be tcp/PORT or udp/PORT, optionally followed by \"from PREFIX[,PREFIX]\" (at most 32 prefixes)", e)
		}
		out = append(out, k)
	}
	return out, nil
}

// parseKeepOpen reads "tcp/22" or "tcp/22 from 192.168.1.0/24,fd00::/8".
func parseKeepOpen(e string) (KeepOpenPort, bool) {
	head, from, ranged := strings.Cut(strings.TrimSpace(e), " from ")
	proto, port, ok := strings.Cut(strings.TrimSpace(head), "/")
	n, err := strconv.ParseUint(port, 10, 16)
	if !ok || proto != "tcp" && proto != "udp" || err != nil || n == 0 || strconv.FormatUint(n, 10) != port {
		return KeepOpenPort{}, false
	}
	k := KeepOpenPort{Proto: proto, Port: uint16(n)}
	if ranged {
		seen := map[string]bool{}
		for _, f := range strings.Split(from, ",") {
			f = strings.TrimSpace(f)
			p, err := netip.ParsePrefix(f)
			if err != nil || p.Masked() != p || p.Addr().Zone() != "" || p.Addr().Is4In6() || seen[f] {
				return KeepOpenPort{}, false
			}
			seen[f] = true
			k.From = append(k.From, f)
		}
		if len(k.From) > 32 {
			return KeepOpenPort{}, false
		}
	}
	return k, true
}

// KeepOpenPort is one keep_open entry. From empty: open from anywhere.
type KeepOpenPort struct {
	Proto string
	Port  uint16
	From  []string
}

// NodeShell is node.yaml node_shell: where the node's own SSH server and
// the sfc-shell account live (docs/reference/node-shell.md). Empty fields
// keep the defaults: 127.0.0.1:22, /etc/ssh/ssh_host_ed25519_key.pub,
// /var/lib/sfc-shell and /etc/sudoers.d.
type NodeShell struct {
	SSHEndpoint   string `yaml:"ssh_endpoint,omitempty" json:",omitempty"`
	HostPublicKey string `yaml:"host_public_key,omitempty" json:",omitempty"`
	Home          string `yaml:"home,omitempty" json:",omitempty"`
	SudoersDir    string `yaml:"sudoers_dir,omitempty" json:",omitempty"`
}

// ClusterApps is node.yaml cluster_apps: the cluster apps this node runs
// (devel/design/cluster-apps.md). sfc-web is brought up or down only here.
type ClusterApps struct {
	Web *ClusterAppWeb `yaml:"web,omitempty" json:",omitempty"`
}

// ClusterAppWeb is cluster_apps.web.
type ClusterAppWeb struct {
	Enabled bool `yaml:"enabled"`
	// SealKeyFile holds sfc-web's seal key; without it sfc-web runs with
	// AI, DNS, certificate automation and notifications off.
	SealKeyFile string `yaml:"seal_key_file,omitempty" json:",omitempty"`
	// UID is the non-root UID the container runs as; it owns the cluster app's
	// management socket and data directory. Empty (or 0: root is never used)
	// is clusterapp.DefaultUID.
	UID uint32 `yaml:"uid,omitempty" json:",omitempty"`
	// Port, when set, opens this TCP port on the server's own address (the
	// host of node.listen) to sfc-web's web port, while this server runs
	// it: the first way in before any ingress route (Jay 2026-11-26).
	// Removing it closes the port.
	Port uint16 `yaml:"port,omitempty" json:",omitempty"`
}

// Enabled lists the enabled cluster apps by cluster app image name.
func (b ClusterApps) Enabled() []string {
	if b.Web != nil && b.Web.Enabled {
		return []string{clusterapp.Web}
	}
	return nil
}

// VaultBackend is installed node-local material, outside the shared manifest.
// Realm and role restrictions cannot be selected by a deployment document.
type VaultBackend struct {
	Mode      string `yaml:"mode,omitempty"`
	Root      string `yaml:"root,omitempty"`
	Realm     string `yaml:"realm"`
	Profile   string `yaml:"profile"`
	Address   string `yaml:"address"`
	Mount     string `yaml:"mount"`
	Prefix    string `yaml:"prefix"`
	Namespace string `yaml:"namespace,omitempty"`
	CAFile    string `yaml:"ca_file"`
	TokenFile string `yaml:"token_file"`
	Values    bool   `yaml:"values"`
	Verifiers bool   `yaml:"verifiers"`
}

// CredentialBackend contains installation paths, never password/token material.
// It is node-local and excluded from the shared Common manifest.
type CredentialBackend struct {
	Profile   string `yaml:"profile"`
	Address   string `yaml:"address"`
	Mount     string `yaml:"mount"`
	Namespace string `yaml:"namespace,omitempty"`
	CAFile    string `yaml:"ca_file"`
	TokenFile string `yaml:"token_file"`
}

// Client is a CLI cluster profile. Every request authenticates as a user;
// installation identities are never a client credential.
type Client struct {
	Version int    `yaml:"version"`
	Cluster string `yaml:"cluster"`
	Peers   []Peer `yaml:"peers"`
	Auth    string `yaml:"auth,omitempty"`
}

func decode(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(b) > 1<<20 {
		return errors.New("configuration exceeds 1MiB")
	}
	var document yaml.Node
	d := yaml.NewDecoder(bytes.NewReader(b))
	if err = d.Decode(&document); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("configuration must contain one YAML document")
	}
	remaining := 10000
	if err = checkTree(&document, 0, &remaining); err != nil {
		return err
	}
	d = yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	return d.Decode(target)
}
func checkTree(n *yaml.Node, depth int, remaining *int) error {
	*remaining--
	if *remaining < 0 || depth > 32 || n.Kind == yaml.AliasNode {
		return errors.New("configuration node/depth/alias budget")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || seen[k.Value] {
				return errors.New("duplicate/non-string configuration key")
			}
			seen[k.Value] = true
		}
	}
	for _, c := range n.Content {
		if err := checkTree(c, depth+1, remaining); err != nil {
			return err
		}
	}
	return nil
}
func ClusterKey(s string) ([32]byte, error) {
	var v [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return v, errors.New("cluster requires 64 hexadecimal characters")
	}
	copy(v[:], b)
	if v == [32]byte{} {
		return v, errors.New("zero cluster ID")
	}
	return v, nil
}
func pathFrom(file, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), value))
}
func endpoint(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	if host == "" || port == "" || port == "0" {
		return errors.New("endpoint needs explicit host and nonzero port")
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 || strings.ContainsAny(host, " \t\r\n") {
		return errors.New("endpoint needs numeric port 1..65535 and a host")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsUnspecified() || ip.IsMulticast()) {
		return errors.New("peer endpoint must be unicast")
	}
	return nil
}

func ValidateEndpoint(s string) error { return endpoint(s) }

// ValidateCanonicalEndpoint is used by managed installation and the committed
// member directory. It compares text deterministically without resolving DNS.
func ValidateCanonicalEndpoint(s string) error {
	if len(s) > 320 {
		return errors.New("peer endpoint exceeds 320 bytes")
	}
	if err := endpoint(s); err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(s)
	number, _ := strconv.ParseUint(port, 10, 16)
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
	}
	if s != net.JoinHostPort(host, strconv.FormatUint(number, 10)) {
		return errors.New("peer endpoint must use canonical host and port")
	}
	return nil
}
func validatePeers(peers []Peer) error {
	return validatePeerSet(peers, false)
}

func validatePeerSet(peers []Peer, management bool) error {
	limit := 32
	if management {
		limit = 64
	}
	if len(peers) == 0 || len(peers) > limit {
		return fmt.Errorf("peer count must be 1..%d", limit)
	}
	ids, keys, addresses := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range peers {
		if p.ID == "" || len(p.ID) > 128 || strings.ContainsAny(p.ID, "/\\ \t\r\n") || ids[p.ID] {
			return errors.New("invalid/duplicate peer ID")
		}
		key, err := identity.ParseKey(p.Key)
		if err != nil {
			return err
		}
		canonical := hex.EncodeToString(key[:])
		if p.Key != canonical || keys[canonical] {
			return errors.New("noncanonical/duplicate peer key")
		}
		if management && strings.HasPrefix(p.Endpoint, "unix:") {
			_, err = cliprofile.ParseEndpoint(p.Endpoint, false)
		} else {
			err = endpoint(p.Endpoint)
		}
		if err != nil {
			return err
		}
		if addresses[p.Endpoint] {
			return errors.New("duplicate peer endpoint")
		}
		ids[p.ID] = true
		keys[canonical] = true
		addresses[p.Endpoint] = true
	}
	return nil
}
func LoadNode(path string) (Node, error) {
	var c Node
	if err := decode(path, &c); err != nil {
		return c, err
	}
	if c.Version != 1 {
		return c, errors.New("configuration version must be 1")
	}
	if c.Node.StateDir == "" || c.Node.IdentityDir == "" || c.Node.Listen == "" {
		return c, errors.New("node needs state_dir, identity_dir and listen")
	}
	if p := c.Node.ManagementSocket; p != "" && (!filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || len(p) > 107 || strings.ContainsAny(p, "\x00\r\n\t\\?#%")) {
		return c, errors.New("management_socket must be a clean absolute Unix socket path")
	}
	if c.Node.ID == "" || len(c.Node.ID) > 63 {
		return c, errors.New("node requires an ID of at most 63 characters")
	}
	for i, ch := range []byte(c.Node.ID) {
		if !(ch >= 'a' && ch <= 'z' || i > 0 && (ch >= '0' && ch <= '9' || ch == '-')) {
			return c, errors.New("node ID must start with lowercase letter and contain lowercase letters, digits or hyphens")
		}
	}
	if err := ValidateCanonicalEndpoint(c.Node.Listen); err != nil {
		return c, err
	}
	if len(c.Modules) != 3 {
		return c, errors.New("modules must select network, workload and ingress")
	}
	for _, name := range []string{"network", "workload", "ingress"} {
		if _, ok := c.Modules[name]; !ok {
			return c, fmt.Errorf("missing module %s", name)
		}
	}
	if m := c.Modules["network"]; m.Enabled {
		if m.has("docker_socket") {
			return c, errors.New("modules.network.docker_socket was removed: sfcd uses the Seafield engine at " + DefaultEngineAPI + "; delete the line from node.yaml")
		}
		var n NetworkLocal
		if err := m.Decode(&n); err != nil {
			return c, err
		}
	}
	if m := c.Modules["workload"]; m.Enabled {
		var w WorkloadLocal
		if err := m.Decode(&w); err != nil {
			return c, err
		}
		if !c.Modules["network"].Enabled {
			return c, errors.New("workload requires network module")
		}
	}
	c.Node.StateDir = pathFrom(path, c.Node.StateDir)
	c.Node.IdentityDir = pathFrom(path, c.Node.IdentityDir)
	if len(c.ServiceCAs) > 64 {
		return c, errors.New("service CAs require a managed catalog and at most64 tenant bundles")
	}
	seenServiceCA := map[string]bool{}
	for i := range c.ServiceCAs {
		p := &c.ServiceCAs[i]
		if !p.valid() || seenServiceCA[p.Tenant] {
			return c, errors.New("invalid or duplicate tenant service CA")
		}
		seenServiceCA[p.Tenant] = true
		p.CAFile = pathFrom(path, p.CAFile)
	}
	if len(c.GitCredentials) > 64 {
		return c, errors.New("Git credentials require a managed catalog and at most64 installed profiles")
	}
	seenGit := map[string]bool{}
	for i := range c.GitCredentials {
		p := &c.GitCredentials[i]
		key := p.Tenant + "/" + p.Profile
		if p.Validate() != nil || seenGit[key] {
			return c, errors.New("invalid or duplicate tenant Git credential profile")
		}
		seenGit[key] = true
		p.PasswordFile = pathFrom(path, p.PasswordFile)
		if p.CAFile != "" {
			p.CAFile = pathFrom(path, p.CAFile)
		}
	}
	if c.Credentials != nil {
		p := c.Credentials
		if p.Profile == "builtin" {
			return c, errors.New("credentials: profile builtin is the cluster's own store; name the external Vault differently")
		}
		if p.Profile == "" || !strings.HasPrefix(p.Address, "https://") || p.Mount == "" || p.CAFile == "" || p.TokenFile == "" {
			return c, errors.New("credentials requires user_catalog and explicit profile/HTTPS address/mount/CA/token-file")
		}
		p.CAFile = pathFrom(path, p.CAFile)
		p.TokenFile = pathFrom(path, p.TokenFile)
	}
	if len(c.Vaults) > 64 {
		return c, errors.New("too many local Vault profiles")
	}
	seenVault := map[string]bool{}
	for i := range c.Vaults {
		p := &c.Vaults[i]
		key := p.Realm + "/" + p.Profile
		if p.Profile == "" || p.Prefix == "" || !p.Values && !p.Verifiers || seenVault[key] {
			return c, errors.New("Vault requires unique installed realm/profile/roles and explicit HTTPS/mount/prefix/CA/token-file")
		}
		seenVault[key] = true
		if p.Mode == "local-file" {
			if p.Root == "" || !p.Values || p.Verifiers || p.Address != "" || p.Mount != "" || p.Namespace != "" || p.CAFile != "" || p.TokenFile != "" {
				return c, errors.New("local-file requires an explicit installed root and values-only role without Vault transport or credentials")
			}
			p.Root = pathFrom(path, p.Root)
			continue
		}
		if p.Mode != "" && p.Mode != "vault" || p.Root != "" || !strings.HasPrefix(p.Address, "https://") || p.Mount == "" || p.CAFile == "" || p.TokenFile == "" {
			return c, errors.New("Vault requires explicit HTTPS/mount/CA/token-file and no local-file root")
		}
		p.CAFile, p.TokenFile = pathFrom(path, p.CAFile), pathFrom(path, p.TokenFile)
	}
	if w := c.ClusterApps.Web; w != nil {
		if w.Enabled && !c.Modules["network"].Enabled {
			return c, errors.New("cluster app web requires network")
		}
		if w.SealKeyFile != "" {
			w.SealKeyFile = pathFrom(path, w.SealKeyFile)
		}
		if w.UID == 0 {
			w.UID = clusterapp.DefaultUID
		}
		if w.UID > math.MaxInt32 {
			return c, errors.New("cluster app web uid must be a non-root UID")
		}
		if _, listen, _ := net.SplitHostPort(c.Node.Listen); w.Port != 0 && strconv.Itoa(int(w.Port)) == listen {
			return c, errors.New("cluster app web port must differ from node.listen")
		}
	}
	if err := c.Engine.Validate(); err != nil {
		return c, err
	}
	if _, err := c.Firewall.KeepOpenPorts(); err != nil {
		return c, err
	}
	if m := c.Modules["ingress"]; m.Enabled {
		var v IngressLocal
		if err := m.Decode(&v); err != nil {
			return c, err
		}
		if !c.Modules["network"].Enabled {
			return c, errors.New("ingress requires network")
		}
		if v.Gateways.Validate() != nil {
			return c, errors.New("invalid ingress gateway configuration")
		}
	}
	return c, nil
}
func LoadClient(path string) (Client, error) {
	var c Client
	if err := decode(path, &c); err != nil {
		return c, err
	}
	if c.Auth == "" {
		c.Auth = "user"
	}
	if c.Version != 1 || c.Auth != "user" {
		return c, errors.New("client needs version=1 and auth: user")
	}
	if _, err := ClusterKey(c.Cluster); err != nil {
		return c, err
	}
	for i := range c.Peers {
		if strings.HasPrefix(c.Peers[i].Endpoint, "sfcp:") || strings.HasPrefix(c.Peers[i].Endpoint, "unix:") {
			e, err := cliprofile.ParseEndpoint(c.Peers[i].Endpoint, false)
			if err != nil {
				return c, err
			}
			if e.Network == "sfcp" {
				c.Peers[i].Endpoint = e.Address
			}
		}
	}
	if err := validatePeerSet(c.Peers, true); err != nil {
		return c, err
	}
	return c, nil
}

// ResolveClient falls through only on a missing automatic candidate. Explicit
// selection errors and any other filesystem error preserve the original cause.
func ResolveClient(file, dir, home, system string) (string, error) {
	if file != "" && dir != "" {
		return "", errors.New("--config and --config-dir are mutually exclusive")
	}
	if dir != "" {
		file = filepath.Join(dir, "client.yaml")
	}
	if file != "" {
		return file, nil
	}
	for _, candidate := range []string{filepath.Join(home, ".sfc", "client.yaml"), filepath.Join(system, "client.yaml")} {
		info, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", errors.New("client configuration is not a regular file")
		}
		return candidate, nil
	}
	return "", os.ErrNotExist
}
