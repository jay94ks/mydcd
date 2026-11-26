// SPDX-License-Identifier: Apache-2.0

package cliprofile

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// The CLI's own files under ~/.mydc (devel/design/cli-and-formats.md):
//
//	config.yaml            contexts: where to connect, as whom, which tenant
//	trust/<cluster>.yaml   node keys confirmed for one cluster
//
// Both are written only by the CLI (a person may edit config.yaml). Neither
// grants remote authority; mydcd checks every request.

var (
	ErrNoContext = errors.New("no context; add one with 'mydc context add NAME [ENDPOINT]'")
	ErrNotFound  = errors.New("no such context")
	ErrExists    = errors.New("a context with that name already exists")
)

// Config is ~/.mydc/config.yaml.
type Config struct {
	Version  int                `yaml:"version"`
	Current  string             `yaml:"current,omitempty"`
	Contexts map[string]Context `yaml:"contexts,omitempty"`
}

// Context is one way to reach a cluster.
type Context struct {
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	Cluster  string `yaml:"cluster" json:"cluster"` // hex cluster ID confirmed on first contact
	User     string `yaml:"user,omitempty" json:"user,omitempty"`
	Tenant   string `yaml:"tenant,omitempty" json:"tenant,omitempty"`
	Key      string `yaml:"key,omitempty" json:"key,omitempty"` // wallet key used by 'mydc login'
}

// Trust is ~/.mydc/trust/<cluster>.yaml: the node keys this user confirmed.
type Trust struct {
	Version int           `yaml:"version" json:"version"`
	Cluster string        `yaml:"cluster" json:"cluster"`
	Nodes   []TrustedNode `yaml:"nodes" json:"nodes"`
}

// TrustedNode is one confirmed node key. How says how it was confirmed:
// "fingerprint" (typed on the terminal) or "out-of-band" (--key).
type TrustedNode struct {
	ID        string    `yaml:"id" json:"id"`
	Key       string    `yaml:"key" json:"key"` // hex public key
	Endpoints []string  `yaml:"endpoints" json:"endpoints"`
	How       string    `yaml:"how" json:"how"`
	At        time.Time `yaml:"at" json:"at"`
}

// ValidUsername checks a login name, which may be any Unicode without
// spaces or control characters.
func ValidUsername(s string) bool {
	if s == "" || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func clusterHex(s string) ([32]byte, error) {
	var id [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != s {
		return id, fmt.Errorf("%w: cluster must be 64 lower-case hex characters", ErrInput)
	}
	copy(id[:], raw)
	if id == ([32]byte{}) {
		return id, ErrInput
	}
	return id, nil
}

// Validate checks one context entry.
func (c Context) Validate() error {
	e, err := ParseEndpoint(c.Endpoint, false)
	if err != nil || e.URI != c.Endpoint {
		return fmt.Errorf("%w: endpoint %q", ErrInput, c.Endpoint)
	}
	if _, err := clusterHex(c.Cluster); err != nil {
		return err
	}
	if c.User != "" && !ValidUsername(c.User) || c.Tenant != "" && !ValidKeyName(c.Tenant) || c.Key != "" && !ValidKeyName(c.Key) {
		return fmt.Errorf("%w: user, tenant or key name", ErrInput)
	}
	return nil
}

// Validate checks the whole file.
func (c Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("%w: config.yaml version must be 1", ErrInput)
	}
	for name, ctx := range c.Contexts {
		if !ValidName(name) {
			return fmt.Errorf("%w: context name %q", ErrInput, name)
		}
		if err := ctx.Validate(); err != nil {
			return fmt.Errorf("context %s: %w", name, err)
		}
	}
	if _, ok := c.Contexts[c.Current]; c.Current != "" && !ok {
		return fmt.Errorf("%w: current context %q is not defined", ErrInput, c.Current)
	}
	return nil
}

// Validate checks a trust file.
func (t Trust) Validate() error {
	if t.Version != 1 {
		return ErrTrust
	}
	if _, err := clusterHex(t.Cluster); err != nil {
		return err
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, n := range t.Nodes {
		raw, err := hex.DecodeString(n.Key)
		if !ValidKeyName(n.ID) || err != nil || len(raw) != 32 || hex.EncodeToString(raw) != n.Key || ids[n.ID] || keys[n.Key] || len(n.Endpoints) == 0 || n.How != "fingerprint" && n.How != "out-of-band" {
			return ErrTrust
		}
		ids[n.ID], keys[n.Key] = true, true
		for _, e := range n.Endpoints {
			if p, err := ParseEndpoint(e, false); err != nil || p.URI != e {
				return ErrTrust
			}
		}
	}
	return nil
}

// Store is ~/.mydc.
type Store struct{ root *os.Root }

// OpenStore opens ~/.mydc, creating it with mode 0700 when create is set.
func OpenStore(home string, create bool) (*Store, error) {
	dir := filepath.Join(home, ".mydc")
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be a private directory (mode 0700)", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

func (s *Store) Close() error { return s.root.Close() }

// Lock serializes writers of ~/.mydc between CLI processes.
func (s *Store) Lock() (func(), error) {
	f, err := s.root.OpenFile(".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

// Load reads config.yaml; a missing file is an empty configuration.
func (s *Store) Load() (Config, error) {
	var c Config
	raw, err := s.root.ReadFile("config.yaml")
	if errors.Is(err, fs.ErrNotExist) {
		return Config{Version: 1}, nil
	}
	if err != nil {
		return c, err
	}
	if err = strictYAML(raw, &c); err != nil {
		return c, fmt.Errorf("~/.mydc/config.yaml: %w", err)
	}
	if err = c.Validate(); err != nil {
		return c, fmt.Errorf("~/.mydc/config.yaml: %w", err)
	}
	return c, nil
}

// Save replaces config.yaml atomically. Hold Lock around Load and Save.
func (s *Store) Save(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	return s.write("config.yaml", c)
}

// Trust reads the trust file of one cluster. A missing file has no nodes.
func (s *Store) Trust(cluster string) (Trust, error) {
	if _, err := clusterHex(cluster); err != nil {
		return Trust{}, err
	}
	var t Trust
	raw, err := s.root.ReadFile(filepath.Join("trust", cluster+".yaml"))
	if errors.Is(err, fs.ErrNotExist) {
		return Trust{Version: 1, Cluster: cluster}, nil
	}
	if err != nil {
		return t, err
	}
	if strictYAML(raw, &t) != nil || t.Validate() != nil || t.Cluster != cluster {
		return Trust{}, fmt.Errorf("~/.mydc/trust/%s.yaml: %w", cluster, ErrTrust)
	}
	return t, nil
}

// SaveTrust replaces a trust file atomically. Hold Lock.
func (s *Store) SaveTrust(t Trust) error {
	if err := t.Validate(); err != nil {
		return err
	}
	slices.SortFunc(t.Nodes, func(a, b TrustedNode) int { return strings.Compare(a.ID, b.ID) })
	if err := s.root.Mkdir("trust", 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return s.write(filepath.Join("trust", t.Cluster+".yaml"), t)
}

// RemoveTrust deletes a cluster's trust file. Hold Lock.
func (s *Store) RemoveTrust(cluster string) error {
	if _, err := clusterHex(cluster); err != nil {
		return err
	}
	err := s.root.Remove(filepath.Join("trust", cluster+".yaml"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Resolve returns the named context, or the current one when name is empty.
func (s *Store) Resolve(name string) (Selection, error) {
	c, err := s.Load()
	if err != nil {
		return Selection{}, err
	}
	if name == "" {
		name = c.Current
	}
	if name == "" {
		return Selection{}, ErrNoContext
	}
	ctx, ok := c.Contexts[name]
	if !ok {
		return Selection{}, fmt.Errorf("%w %q", ErrNotFound, name)
	}
	trust, err := s.Trust(ctx.Cluster)
	if err != nil {
		return Selection{}, err
	}
	return Select(name, ctx, trust)
}

// Names lists the contexts in name order.
func (c Config) Names() []string {
	names := make([]string, 0, len(c.Contexts))
	for name := range c.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (s *Store) write(name string, value any) error {
	var b bytes.Buffer
	e := yaml.NewEncoder(&b)
	e.SetIndent(2)
	if err := e.Encode(value); err != nil {
		return err
	}
	if err := e.Close(); err != nil {
		return err
	}
	tmp := name + ".tmp"
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b.Bytes()); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = s.root.Rename(tmp, name)
	}
	if err != nil {
		_ = s.root.Remove(tmp)
	}
	return err
}

func strictYAML(raw []byte, out any) error {
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	return d.Decode(out)
}
