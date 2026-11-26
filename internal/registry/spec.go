// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"net/url"
	"strconv"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Specification is tenant management metadata, not an app declaration or an
// observation that a listener, certificate, writer or registry is ready.
type Specification struct {
	Schema                         uint8
	Tenant, ID, Node               string
	Address, Authority             string
	Volume                         volumes.Scope
	Enabled                        bool
	Metadata                       MetadataLimits
	Blobs                          BlobLimits
	Budget                         workload.Resources
	MaxRequests, MaxHeaderBytes    int
	RequestTimeoutMS, TokenSeconds uint64
}

func (s Specification) Validate(cluster [32]byte) error {
	addr, err := netip.ParseAddrPort(s.Address)
	if err != nil || addr.String() != s.Address || addr.Port() == 0 || addr.Addr().Zone() != "" || addr.Addr().Is4In6() || addr.Addr().IsMulticast() {
		return ErrStorage
	}
	u, err := url.Parse("https://" + s.Authority)
	if err != nil || u.Host != s.Authority || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ErrStorage
	}
	if _, err = access.CanonicalTrust([]access.TrustRule{{Registry: s.Authority, Repository: "**"}}); err != nil {
		return ErrStorage
	}
	port := uint64(443)
	if u.Port() != "" {
		port, err = strconv.ParseUint(u.Port(), 10, 16)
		if err != nil {
			return ErrStorage
		}
	}
	if port != uint64(addr.Port()) {
		return ErrStorage
	}
	if s.Schema != 1 || cluster == ([32]byte{}) || !scopeName(s.Tenant) || !scopeName(s.ID) || !scopeName(s.Node) || s.Volume.Cluster != cluster || s.Volume.Tenant != s.Tenant || !scopeName(s.Volume.ID) || s.Volume.Generation == 0 || s.Volume.App != "" || s.Volume.Registry != "" && s.Volume.Registry != s.ID {
		return ErrStorage
	}
	if !s.Metadata.valid() || !s.Blobs.valid() || s.Budget.CPU == 0 || s.Budget.Memory == 0 || s.MaxRequests < 1 || s.MaxRequests > 256 || s.MaxHeaderBytes < 4096 || s.MaxHeaderBytes > 64<<10 || s.RequestTimeoutMS < 100 || s.RequestTimeoutMS > 300000 || s.TokenSeconds < 1 || s.TokenSeconds > 300 {
		return ErrStorage
	}
	return nil
}

func (s Specification) Digest() [32]byte {
	raw, _ := json.Marshal(s)
	return sha256.Sum256(append([]byte("mydc-registry-spec-1\x00"), raw...))
}
func (s Specification) Key() string { return s.Tenant + "/" + s.ID }
func (s Specification) BudgetKey() string {
	return "workload/registry/" + s.Tenant + "/" + s.ID + "/server"
}
