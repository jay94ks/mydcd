// SPDX-License-Identifier: Apache-2.0

// Package config loads installation-local files without opening runtime resources.
package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/nodeapp"
	"io"
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
	Enabled      bool   `yaml:"enabled"`
	DockerSocket string `yaml:"docker_socket"`
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
	} `yaml:"node"`
	Modules        map[string]Module  `yaml:"modules"`
	Credentials    *CredentialBackend `yaml:"credentials,omitempty" json:",omitempty"`
	Vaults         []VaultBackend     `yaml:"vaults,omitempty" json:",omitempty"`
	ServiceCAs     []ServiceCA        `yaml:"service_cas,omitempty" json:",omitempty"`
	GitCredentials []GitCredential    `yaml:"git_credentials,omitempty" json:",omitempty"`
	NodeApps       NodeApps           `yaml:"node_apps,omitempty" json:",omitempty"`
	NodeShell      NodeShell          `yaml:"node_shell,omitempty" json:",omitempty"`
}

// NodeShell is node.yaml node_shell: where the node's own SSH server and
// the mydc-shell account live (docs/reference/node-shell.md). Empty fields
// keep the defaults: 127.0.0.1:22, /etc/ssh/ssh_host_ed25519_key.pub,
// /var/lib/mydc-shell and /etc/sudoers.d.
type NodeShell struct {
	SSHEndpoint   string `yaml:"ssh_endpoint,omitempty" json:",omitempty"`
	HostPublicKey string `yaml:"host_public_key,omitempty" json:",omitempty"`
	Home          string `yaml:"home,omitempty" json:",omitempty"`
	SudoersDir    string `yaml:"sudoers_dir,omitempty" json:",omitempty"`
}

// NodeApps is node.yaml node_apps: the node apps this node runs
// (devel/design/node-apps.md). mydc-web is brought up or down only here.
type NodeApps struct {
	Web *NodeAppWeb `yaml:"web,omitempty" json:",omitempty"`
}

// NodeAppWeb is node_apps.web.
type NodeAppWeb struct {
	Enabled bool `yaml:"enabled"`
	// SealKeyFile holds mydc-web's seal key; without it mydc-web runs with
	// AI, DNS, certificate automation and notifications off.
	SealKeyFile string `yaml:"seal_key_file,omitempty" json:",omitempty"`
}

// Enabled lists the enabled node apps by node app image name.
func (b NodeApps) Enabled() []string {
	if b.Web != nil && b.Web.Enabled {
		return []string{nodeapp.Web}
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
		var n NetworkLocal
		if err := m.Decode(&n); err != nil {
			return c, err
		}
		if !strings.HasPrefix(n.DockerSocket, "unix:///") || strings.TrimPrefix(n.DockerSocket, "unix://") == "/" {
			return c, errors.New("network needs explicit absolute Docker UDS")
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
	if w := c.NodeApps.Web; w != nil {
		if w.Enabled && !c.Modules["network"].Enabled {
			return c, errors.New("node app web requires network")
		}
		if w.SealKeyFile != "" {
			w.SealKeyFile = pathFrom(path, w.SealKeyFile)
		}
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
		if strings.HasPrefix(c.Peers[i].Endpoint, "mydcp:") || strings.HasPrefix(c.Peers[i].Endpoint, "unix:") {
			e, err := cliprofile.ParseEndpoint(c.Peers[i].Endpoint, false)
			if err != nil {
				return c, err
			}
			if e.Network == "mydcp" {
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
	for _, candidate := range []string{filepath.Join(home, ".mydc", "client.yaml"), filepath.Join(system, "client.yaml")} {
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
