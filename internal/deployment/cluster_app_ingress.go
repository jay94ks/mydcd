// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/ingress"
	"gopkg.in/yaml.v3"
)

// A cluster app's ingress routes come from an app.yaml-shaped file whose app
// name is ClusterAppPrefix + the cluster app (devel/design/cluster-apps.md 3.2). The
// file holds only x-sfc.ingress; the backend is the cluster app itself, on
// the system network at a fixed port and health path.
const (
	ClusterAppPrefix = "cluster-app/"
	// ClusterAppTenant stands for "no workspace" in ingress: never a tenant ID.
	ClusterAppTenant     = "@system"
	clusterAppNetwork    = "sfc-system"
	clusterAppPort       = 8080
	clusterAppHealthPath = "/healthz"
)

// ClusterAppRoutable lists the cluster apps that take routes.
var ClusterAppRoutable = []string{"web"}

// ClusterAppName is the cluster app an app name names ("cluster-app/web" → "web").
func ClusterAppName(name string) (string, bool) {
	app, ok := strings.CutPrefix(name, ClusterAppPrefix)
	for _, a := range ClusterAppRoutable {
		if ok && app == a {
			return app, true
		}
	}
	return "", false
}

var ErrClusterAppRoutes = errors.New("a cluster app route file holds only name and x-sfc.ingress")

// ParseClusterAppRoutes reads a cluster app route file. Anything but the name and
// x-sfc.ingress (services, volumes, secrets, networks, CD) is refused.
func ParseClusterAppRoutes(raw []byte) (string, IngressDeclaration, error) {
	var doc struct {
		Name string `yaml:"name"`
		Sfc  struct {
			Ingress *IngressDeclaration `yaml:"ingress"`
		} `yaml:"x-sfc"`
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if err := d.Decode(&doc); err != nil {
		return "", IngressDeclaration{}, errors.Join(ErrClusterAppRoutes, err)
	}
	app, ok := ClusterAppName(doc.Name)
	if !ok || doc.Sfc.Ingress == nil {
		return "", IngressDeclaration{}, ErrClusterAppRoutes
	}
	if err := ValidateClusterAppIngress(*doc.Sfc.Ingress); err != nil {
		return "", IngressDeclaration{}, err
	}
	return app, *doc.Sfc.Ingress, nil
}

// ValidateClusterAppIngress checks a cluster app's ingress: the app.yaml rules
// for node, listeners, routes and runtime, with no backend of its own.
func ValidateClusterAppIngress(i IngressDeclaration) error {
	if i.Backend.Service != "" || i.Backend.Network != "" || i.Backend.Port != 0 || i.Backend.HealthPath != "" {
		return inputError("CLUSTER_APP_BACKEND_FIXED", "x-sfc.ingress.backend")
	}
	for _, r := range i.Routes {
		if r.Service != "" || r.Network != "" || r.Port != 0 || r.HealthPath != "" {
			return inputError("CLUSTER_APP_BACKEND_FIXED", r.ID)
		}
	}
	if i.Runtime.validate() != nil || !identifier(i.Node) || len(i.Listeners) > 16 || len(i.Routes) > 256 || len(i.Routes) > 0 && i.Host != "" || len(i.Routes) == 0 && i.Host == "" {
		return inputError("INVALID_INGRESS", "x-sfc.ingress")
	}
	if len(i.Listeners) == 0 {
		i.Listeners = []ListenerDeclaration{{Shared: "validate"}} // filled from the node's gateways when served
	}
	_, err := ClusterAppIngressSpec("validate", "web", i, &ClusterAppBackend{Address: netip.MustParseAddr("192.0.2.1")}, 1)
	if err != nil {
		return inputError("INVALID_INGRESS", "x-sfc.ingress")
	}
	return nil
}

// ClusterAppBackend is where the cluster app listens now (devel/design/cluster-apps.md
// 3.2: the one serving endpoint), on Node.
type ClusterAppBackend struct {
	Node    string
	Address netip.Addr
}

// ClusterAppIngressSpec is the ingress spec for a cluster app's routes on their
// node. Backends follow the endpoint (dynamic), so a new address does not
// restart the listeners; binding is the system network revision it was
// read at. backend nil: no endpoint yet, so requests get 502.
func ClusterAppIngressSpec(owner, app string, i IngressDeclaration, backend *ClusterAppBackend, binding uint64) (ingress.Spec, error) {
	s := i.Runtime.spec()
	s.Schema, s.Owner, s.Tenant, s.App = 1, owner, ClusterAppTenant, ClusterAppPrefix+app
	s.DynamicBackends, s.BindingRevision = true, binding
	for n, l := range i.Listeners {
		s.Listeners = append(s.Listeners, ingress.Listener{ID: "listener-" + strconv.Itoa(n+1), Address: l.Address, TLS: l.TLS, HTTP3: l.HTTP3, Shared: l.Shared})
	}
	var backends []ingress.BackendSpec
	if backend != nil {
		backends = []ingress.BackendSpec{{ID: app, Task: ClusterAppPrefix + app, Network: clusterAppNetwork, Node: backend.Node, Generation: 1, Revision: binding, Address: backend.Address, Port: clusterAppPort, Weight: 1, Capacity: s.MaxRequests, HealthPath: clusterAppHealthPath}}
	}
	s.Services = []ingress.Service{{ID: app, Backends: backends}}
	for _, r := range IngressRoutes(i) {
		s.Routes = append(s.Routes, ingress.Route{ID: r.ID, Host: r.Host, Prefix: r.Prefix, Service: app, Gateway: r.Gateway, Balance: r.Balance})
	}
	raw, _ := json.Marshal(s)
	return ingress.DecodeSpec(string(raw))
}
