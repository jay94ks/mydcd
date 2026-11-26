// SPDX-License-Identifier: Apache-2.0

// Package config holds mydc-web daemon settings.
package config

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config is the daemon configuration. Every field has a flag and an
// environment variable (flag wins).
type Config struct {
	Listen  string // HTTP listen address
	TLSCert string // optional TLS certificate file
	TLSKey  string // optional TLS key file
	Socket  string // mydcd Unix socket path (mounted into the container)
	// Cluster, Node and NodeKey pin the mydcd behind Socket (hex cluster ID,
	// node ID, hex node identity key), as a CLI context trusts a node out of
	// band. Required.
	Cluster       string
	Node          string
	NodeKey       string
	DataDir       string        // directory of web.db
	StaticDir     string        // serve the UI from disk instead of the embedded build
	ACMEListen    string        // ACME HTTP-01 responder address (empty: off)
	ACMEAdvertise string        // responder IP:port ingress dials (default: ACMEListen when it is a concrete IP:port)
	CookieSecure  bool          // set Secure on the session cookie
	OpRetention   time.Duration // keep settled ops this long
	LoginTimeout  time.Duration // pending login (ticket) lifetime
	SealKey       string        // MYDC_WEB_SEAL_KEY (hex or base64 of 32 bytes); env only, never a flag
	SealKeyFile   string        // file holding the seal key (a Docker secret)
	// SealKeyNext / SealKeyNextFile: a new seal key. On start every sealed
	// file is sealed again with it; then it replaces SealKey.
	SealKeyNext     string
	SealKeyNextFile string
	// AI vendor base URLs (empty: the public APIs; set for a proxy) and the
	// file of OpenAI model ID patterns to hide from role pickers (one Go
	// regexp per line, # comments; empty: the built-in list).
	AIClaudeURL     string
	AIOpenAIURL     string
	AIHideModelFile string
}

// Default returns the defaults.
func Default() Config {
	return Config{
		Listen:       ":8080",
		Socket:       "/var/run/mydc.sock",
		DataDir:      "/var/lib/mydc-web",
		CookieSecure: true,
		OpRetention:  30 * 24 * time.Hour,
		LoginTimeout: 5 * time.Minute,
	}
}

// Parse reads flags and MYDC_WEB_* environment variables.
func Parse(args []string, getenv func(string) string) (Config, error) {
	c := Default()
	env := func(name string, dst *string) {
		if v := getenv(name); v != "" {
			*dst = v
		}
	}
	env("MYDC_WEB_LISTEN", &c.Listen)
	env("MYDC_WEB_TLS_CERT", &c.TLSCert)
	env("MYDC_WEB_TLS_KEY", &c.TLSKey)
	env("MYDC_WEB_SOCKET", &c.Socket)
	env("MYDC_WEB_CLUSTER", &c.Cluster)
	env("MYDC_WEB_NODE", &c.Node)
	env("MYDC_WEB_NODE_KEY", &c.NodeKey)
	env("MYDC_WEB_DATA_DIR", &c.DataDir)
	env("MYDC_WEB_STATIC_DIR", &c.StaticDir)
	env("MYDC_WEB_ACME_LISTEN", &c.ACMEListen)
	env("MYDC_WEB_ACME_ADVERTISE", &c.ACMEAdvertise)
	env("MYDC_WEB_SEAL_KEY", &c.SealKey)
	env("MYDC_WEB_SEAL_KEY_FILE", &c.SealKeyFile)
	env("MYDC_WEB_SEAL_KEY_NEXT", &c.SealKeyNext)
	env("MYDC_WEB_SEAL_KEY_NEXT_FILE", &c.SealKeyNextFile)
	env("MYDC_WEB_AI_CLAUDE_URL", &c.AIClaudeURL)
	env("MYDC_WEB_AI_OPENAI_URL", &c.AIOpenAIURL)
	env("MYDC_WEB_AI_HIDE_MODELS_FILE", &c.AIHideModelFile)
	if v := getenv("MYDC_WEB_COOKIE_SECURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("MYDC_WEB_COOKIE_SECURE: %w", err)
		}
		c.CookieSecure = b
	}
	if v := getenv("MYDC_WEB_OP_RETENTION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("MYDC_WEB_OP_RETENTION: %w", err)
		}
		c.OpRetention = d
	}

	fs := flag.NewFlagSet("mydc-web", flag.ContinueOnError)
	fs.StringVar(&c.Listen, "listen", c.Listen, "HTTP listen address")
	fs.StringVar(&c.TLSCert, "tls-cert", c.TLSCert, "TLS certificate file (optional)")
	fs.StringVar(&c.TLSKey, "tls-key", c.TLSKey, "TLS key file (optional)")
	fs.StringVar(&c.Socket, "socket", c.Socket, "mydcd Unix socket path")
	fs.StringVar(&c.Cluster, "cluster", c.Cluster, "cluster ID of the mydcd behind the socket (hex)")
	fs.StringVar(&c.Node, "node", c.Node, "node ID of the mydcd behind the socket")
	fs.StringVar(&c.NodeKey, "node-key", c.NodeKey, "identity key of the mydcd behind the socket (hex)")
	fs.StringVar(&c.DataDir, "data-dir", c.DataDir, "directory for web.db")
	fs.StringVar(&c.ACMEListen, "acme-listen", c.ACMEListen, "plain HTTP address of the ACME HTTP-01 responder that ingress forwards /.well-known/acme-challenge/ to (empty: off)")
	fs.StringVar(&c.ACMEAdvertise, "acme-advertise", c.ACMEAdvertise, "IP:port ingress dials to reach the responder; filled into the cluster setting (default: -acme-listen when it is a concrete IP:port)")
	fs.StringVar(&c.StaticDir, "static-dir", c.StaticDir, "serve UI files from this directory instead of the embedded build")
	fs.BoolVar(&c.CookieSecure, "cookie-secure", c.CookieSecure, "set Secure on the session cookie")
	fs.StringVar(&c.SealKeyFile, "seal-key-file", c.SealKeyFile, "file holding the seal key for sealed secrets (MYDC_WEB_SEAL_KEY is the env alternative)")
	fs.StringVar(&c.SealKeyNextFile, "seal-key-next-file", c.SealKeyNextFile, "file holding a new seal key; sealed files are sealed again with it on start")
	fs.StringVar(&c.AIHideModelFile, "ai-hide-models-file", c.AIHideModelFile, "file of OpenAI model ID patterns hidden from AI role pickers (one regexp per line)")
	fs.DurationVar(&c.OpRetention, "op-retention", c.OpRetention, "keep settled operations this long")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	return c, c.validate()
}

func (c Config) validate() error {
	if _, err := c.ClusterKey(); err != nil {
		return err
	}
	if _, err := c.NodeIdentityKey(); err != nil {
		return err
	}
	if c.Node == "" {
		return errors.New("node is required")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls-cert and tls-key must be set together")
	}
	if c.DataDir == "" {
		return errors.New("data-dir is required")
	}
	if c.SealKey != "" && c.SealKeyFile != "" {
		return errors.New("set MYDC_WEB_SEAL_KEY or seal-key-file, not both")
	}
	if c.SealKeyNext != "" && c.SealKeyNextFile != "" {
		return errors.New("set MYDC_WEB_SEAL_KEY_NEXT or seal-key-next-file, not both")
	}
	return nil
}

// SealKeySource is where the seal key comes from: "env", "file" or "" (none).
func (c Config) SealKeySource() string {
	switch {
	case c.SealKey != "":
		return "env"
	case c.SealKeyFile != "":
		return "file"
	}
	return ""
}

// DBPath is the bbolt file path.
func (c Config) DBPath() string { return c.DataDir + string(os.PathSeparator) + "web.db" }

// SecretsDir is the sealed file folder.
func (c Config) SecretsDir() string { return c.DataDir + string(os.PathSeparator) + "secrets" }

// ReadSealKey returns the seal key text from the env value or the key file
// ("" when neither is set).
func (c Config) ReadSealKey() (string, error) { return readKey(c.SealKey, c.SealKeyFile) }

// ReadSealKeyNext returns the new seal key text ("" when none).
func (c Config) ReadSealKeyNext() (string, error) { return readKey(c.SealKeyNext, c.SealKeyNextFile) }

func readKey(val, file string) (string, error) {
	if file == "" {
		return val, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("seal key file: %w", err)
	}
	return string(b), nil
}

// RestorePath is where a staged restore of web.db waits for the next start.
func (c Config) RestorePath() string { return c.DataDir + string(os.PathSeparator) + "web.db.restore" }

// AIHideModels reads the hide pattern file (nil when not set: the built-in
// list). Each pattern must compile.
func (c Config) AIHideModels() ([]string, error) {
	if c.AIHideModelFile == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(c.AIHideModelFile)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := regexp.Compile(line); err != nil {
			return nil, fmt.Errorf("%s: %w", c.AIHideModelFile, err)
		}
		out = append(out, line)
	}
	return out, nil
}

// ClusterKey decodes Cluster.
func (c Config) ClusterKey() ([32]byte, error) { return hexKey("cluster", c.Cluster) }

// NodeIdentityKey decodes NodeKey.
func (c Config) NodeIdentityKey() ([32]byte, error) { return hexKey("node-key", c.NodeKey) }

func hexKey(name, s string) ([32]byte, error) {
	var k [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("%s: 64 hexadecimal characters required for the socket backend", name)
	}
	copy(k[:], b)
	if k == ([32]byte{}) {
		return k, fmt.Errorf("%s: zero key", name)
	}
	return k, nil
}

// ACMEAdvertiseAddress is the responder address to fill into the cluster
// setting: -acme-advertise, else -acme-listen when it is a concrete IP:port
// (not 0.0.0.0 or ::), else empty.
func (c Config) ACMEAdvertiseAddress() string {
	if c.ACMEListen == "" {
		return ""
	}
	if c.ACMEAdvertise != "" {
		return c.ACMEAdvertise
	}
	if ap, err := netip.ParseAddrPort(c.ACMEListen); err == nil && !ap.Addr().IsUnspecified() {
		return ap.String()
	}
	return ""
}
