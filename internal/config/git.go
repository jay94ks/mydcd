// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"net/url"
	"strings"

	"github.com/jay94ks/mydcd/internal/cliprofile"
)

// GitCredential is installation-local scope and file references, never secret
// material. A profile belongs to one tenant and one exact HTTPS repository.
type GitCredential struct {
	Tenant       string `yaml:"tenant"`
	Profile      string `yaml:"profile"`
	Repository   string `yaml:"repository"`
	Username     string `yaml:"username"`
	PasswordFile string `yaml:"password_file"`
	CAFile       string `yaml:"ca_file,omitempty"`
}

func (p GitCredential) Validate() error {
	u, err := url.Parse(p.Repository)
	if err != nil || !cliprofile.ValidKeyName(p.Tenant) || !cliprofile.ValidKeyName(p.Profile) || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(p.Repository, "\x00\r\n") || p.PasswordFile == "" || len(p.Username) == 0 || len(p.Username) > 256 || strings.ContainsAny(p.Username, ":\x00\r\n") {
		return errors.New("invalid installed Git credential scope")
	}
	return nil
}
