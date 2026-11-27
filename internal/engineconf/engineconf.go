// SPDX-License-Identifier: Apache-2.0

// Package engineconf writes the Seafield engine's daemon.json from
// node.yaml: the fixed values every sfcd server's engine runs with
// (seafield/docs/changes.md) and the per-server engine section.
package engineconf

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"github.com/jay94ks/seafield/internal/config"
)

// DefaultPath is where the node package's sfed.service reads it.
const DefaultPath = "/etc/sfe/daemon.json"

type logOpts struct {
	CacheDisabled string `json:"cache-disabled"`
	NotifyQuiet   string `json:"notify-quiet"`
	NotifyMaxWait string `json:"notify-max-wait"`
	MaxSize       string `json:"max-size"`
}

type daemon struct {
	DataRoot      string          `json:"data-root"`
	ExecRoot      string          `json:"exec-root"`
	Pidfile       string          `json:"pidfile"`
	Hosts         []string        `json:"hosts"`
	Bridge        string          `json:"bridge"`
	IPTables      bool            `json:"iptables"`
	IP6Tables     bool            `json:"ip6tables"`
	UserlandProxy bool            `json:"userland-proxy"`
	LiveRestore   bool            `json:"live-restore"`
	LogDriver     string          `json:"log-driver"`
	LogOpts       logOpts         `json:"log-opts"`
	Features      map[string]bool `json:"features"`
}

// Render is the engine's daemon.json for e, checked as node.yaml is.
func Render(e config.Engine) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	quiet, _ := e.Logs.NotifyQuietDuration()
	wait, _ := e.Logs.NotifyMaxWaitDuration()
	size, _ := e.Logs.MaxSizeBytes()
	d := daemon{
		DataRoot:    "/var/lib/sfe",
		ExecRoot:    "/run/sfe",
		Pidfile:     "/run/sfe/sfed.pid",
		Hosts:       []string{"unix:///run/sfe/sfed.sock"},
		Bridge:      "none",
		LiveRestore: true,
		LogDriver:   "seafield-queue",
		LogOpts:     logOpts{CacheDisabled: "true", NotifyQuiet: quiet.String(), NotifyMaxWait: wait.String(), MaxSize: strconv.FormatInt(size>>10, 10) + "k"},
		Features:    map[string]bool{"buildkit": e.BuildEnabled()},
	}
	b, err := json.MarshalIndent(d, "", "  ")
	return append(b, '\n'), err
}

// Write puts Render(e) at path when it differs from what is there, in one
// rename, mode 0644. changed reports whether the engine must be restarted
// for it to take effect.
func Write(path string, e config.Engine) (changed bool, err error) {
	b, err := Render(e)
	if err != nil {
		return false, err
	}
	if !filepath.IsAbs(path) {
		return false, errors.New("engine config path must be absolute")
	}
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b) {
		return false, nil
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".daemon.json.")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	return err == nil, err
}
