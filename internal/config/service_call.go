// SPDX-License-Identifier: Apache-2.0

package config

import "github.com/jay94ks/seafield/internal/cliprofile"

// ServiceCA is an installed tenant trust bundle, never a user-supplied host
// path or a server certificate/private key.
type ServiceCA struct {
	Tenant string `yaml:"tenant"`
	CAFile string `yaml:"ca_file"`
}

func (p ServiceCA) valid() bool { return cliprofile.ValidKeyName(p.Tenant) && p.CAFile != "" }
