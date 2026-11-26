// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// Compose is the bounded, single-document application input. No field contains
// a fetched Secret, password, node private key, or installed credential. The
// parser performs no file reads, interpolation, network calls, or native work.
type Compose struct {
	Standalone bool                      `yaml:"-" json:",omitempty"`
	Name       string                    `yaml:"name"`
	Services   map[string]ComposeService `yaml:"services"`
	Networks   map[string]ComposeNetwork `yaml:"networks,omitempty"`
	Volumes    map[string]ComposeVolume  `yaml:"volumes,omitempty"`
	Secrets    map[string]ComposeSecret  `yaml:"secrets,omitempty"`
	MyDC       AppExtension              `yaml:"x-mydc,omitempty"`
}
type ComposeService struct {
	Ports      []workload.PublishedPort `yaml:"ports,omitempty" json:",omitempty"`
	Standalone bool                     `yaml:"-" json:",omitempty"`
	WorkingDir string                   `yaml:"working_dir,omitempty" json:",omitempty"`
	TTY        bool                     `yaml:"tty,omitempty" json:",omitempty"`
	StdinOpen  bool                     `yaml:"stdin_open,omitempty" json:",omitempty"`
	// Internal accepted selection. Raw app input cannot specify source facts.
	LifecycleSources *checker.Selection   `yaml:"-" json:",omitempty"`
	LifecycleProgram *checker.TaskProgram `yaml:"-" json:",omitempty"`
	// Frozen Task goal metadata only. It cannot be supplied by app.yaml and
	// remains absent from Input; the compiler derives it from registrations.
	FixedVolumes    map[string]VolumeReference `yaml:"-" json:",omitempty"`
	Image           string                     `yaml:"image"`
	Command         *Arguments                 `yaml:"command,omitempty"`
	Entrypoint      *Arguments                 `yaml:"entrypoint,omitempty"`
	Environment     Environment                `yaml:"environment,omitempty"`
	User            string                     `yaml:"user,omitempty"`
	StopGracePeriod string                     `yaml:"stop_grace_period,omitempty" json:",omitempty"`
	StopSignal      string                     `yaml:"stop_signal,omitempty" json:",omitempty"`
	ReadOnly        *bool                      `yaml:"read_only,omitempty"`
	CapDrop         []string                   `yaml:"cap_drop,omitempty"`
	SecurityOpt     []string                   `yaml:"security_opt,omitempty"`
	CPUs            string                     `yaml:"cpus,omitempty"`
	Memory          string                     `yaml:"mem_limit,omitempty"`
	Tmpfs           []string                   `yaml:"tmpfs,omitempty"`
	DependsOn       Dependencies               `yaml:"depends_on,omitempty"`
	Networks        map[string]Attachment      `yaml:"networks,omitempty"`
	Volumes         Mounts                     `yaml:"volumes,omitempty"`
	Secrets         SecretMounts               `yaml:"secrets,omitempty"`
	Logging         *workload.LogPolicy        `yaml:"logging,omitempty" json:",omitempty"`
	Healthcheck     *Healthcheck               `yaml:"healthcheck,omitempty"`
	DNS             []string                   `yaml:"dns,omitempty"`
	DNSSearch       []string                   `yaml:"dns_search,omitempty"`
	MyDC            ServiceExtension           `yaml:"x-mydc,omitempty"`
	Labels          map[string]string          `yaml:"labels,omitempty" json:",omitempty"`
}
type Arguments []string
type Environment map[string]string
type Dependencies map[string]ServiceDependency
type ServiceDependency struct {
	Condition string `yaml:"condition"`
}
type Attachment struct {
	IPv4    string   `yaml:"ipv4_address,omitempty"`
	IPv6    string   `yaml:"ipv6_address,omitempty"`
	Aliases []string `yaml:"aliases,omitempty" json:",omitempty"`
}
type Mounts []Mount
type Mount struct {
	Type     string `yaml:"type"`
	Source   string `yaml:"source"`
	Target   string `yaml:"target"`
	ReadOnly bool   `yaml:"read_only,omitempty"`
}
type SecretMounts []SecretMount
type SecretMount struct {
	Source string `yaml:"source"`
	Target string `yaml:"target,omitempty"`
	UID    string `yaml:"uid,omitempty"`
	GID    string `yaml:"gid,omitempty"`
	Mode   string `yaml:"mode,omitempty"`
}
type Healthcheck struct {
	Test          []string `yaml:"test"`
	Interval      string   `yaml:"interval,omitempty"`
	Timeout       string   `yaml:"timeout,omitempty"`
	Retries       int      `yaml:"retries,omitempty"`
	StartPeriod   string   `yaml:"start_period,omitempty"`
	StartInterval string   `yaml:"start_interval,omitempty" json:",omitempty"`
	Disable       bool     `yaml:"disable,omitempty" json:",omitempty"`
}
type Readiness struct {
	Kind    string `yaml:"kind"`
	Path    string `yaml:"path,omitempty"`
	Port    uint16 `yaml:"port,omitempty"`
	Timeout string `yaml:"timeout,omitempty" json:",omitempty"`
}
type Selector struct {
	Secret string `yaml:"secret,omitempty"`
	Group  string `yaml:"group,omitempty"`
	Scope  string `yaml:"scope,omitempty"` // tenant (default) or cluster
}
type SecretEnvironment struct {
	Source string `yaml:"source"`
	Name   string `yaml:"name"`
}

type ServiceExtension struct {
	Instance  *TaskInstance       `yaml:"-" json:",omitempty"`
	Nodes     []string            `yaml:"nodes,omitempty" json:",omitempty"`
	PerNode   uint32              `yaml:"per_node,omitempty" json:",omitempty"`
	SecretEnv []SecretEnvironment `yaml:"secret_env,omitempty" json:",omitempty"`
	Node      string              `yaml:"node,omitempty"`
	Readiness *Readiness          `yaml:"ready,omitempty"`
	Sources   SecretSources       `yaml:"secrets_from,omitempty"`
	Lifecycle *ServiceLifecycle   `yaml:"lifecycle,omitempty" json:",omitempty"`
}
type ComposeNetwork struct {
	Name     string           `yaml:"name,omitempty"`
	External bool             `yaml:"external,omitempty"`
	Driver   string           `yaml:"driver,omitempty"`
	MyDC     NetworkExtension `yaml:"x-mydc,omitempty"`
}
type NetworkExtension struct {
	MTU             int                        `yaml:"mtu,omitempty"`
	Pools           map[string]PoolDeclaration `yaml:"pools,omitempty"`
	TunnelAddresses map[string]string          `yaml:"tunnel_addresses,omitempty"`
	RuntimeChanges  *RuntimeChanges            `yaml:"runtime_changes,omitempty"`
	DNS             *DNSDeclaration            `yaml:"dns,omitempty"`
}
type PoolDeclaration struct {
	CIDR        string       `yaml:"cidr"`
	Gateway     string       `yaml:"gateway"`
	AddressPlan *AddressPlan `yaml:"address_plan,omitempty"`
}
type AddressPlan struct {
	DockerRange string `yaml:"docker_ip_range"`
	StaticFirst string `yaml:"static_first"`
	StaticLast  string `yaml:"static_last"`
}
type DNSDeclaration struct {
	Enabled     bool     `yaml:"enabled"`
	Reverse     bool     `yaml:"reverse,omitempty" json:",omitempty"`
	Zone        string   `yaml:"zone"`
	TTL         uint32   `yaml:"ttl_seconds"`
	NegativeTTL uint32   `yaml:"negative_ttl_seconds"`
	Transports  []string `yaml:"transports"`
	Forward     struct {
		Enabled   bool     `yaml:"enabled"`
		Upstreams []string `yaml:"upstreams"`
	} `yaml:"forward"`
	Records []struct {
		Name string `yaml:"name"`
		Task string `yaml:"task"`
	} `yaml:"records"`
	Limits struct {
		Cache    int `yaml:"cache_entries"`
		Inflight int `yaml:"queries_inflight"`
		TCP      int `yaml:"tcp_connections"`
		Timeout  int `yaml:"request_timeout_ms"`
	} `yaml:"limits"`
}
type RuntimeChanges struct {
	Authority    string   `yaml:"authority"`
	Restart      bool     `yaml:"daemon_restart"`
	Strategy     string   `yaml:"strategy"`
	Deadlines    string   `yaml:"existing_lease_deadlines"`
	Disruptive   string   `yaml:"disruptive_changes"`
	StatusFields []string `yaml:"status_fields"`
}
type ComposeVolume struct {
	Name     string          `yaml:"name,omitempty"`
	External bool            `yaml:"external,omitempty"`
	Driver   string          `yaml:"driver,omitempty"`
	MyDC     VolumeExtension `yaml:"x-mydc,omitempty"`
}
type VolumeExtension struct {
	Node string `yaml:"node,omitempty"`
	// Driver, Access, Retain and Quota are fixed defaults (normalize); the
	// app.yaml has no keys for them. Backup and Migration are options of
	// the volume commands, not of app.yaml.
	Driver   string     `yaml:"-"`
	Access   string     `yaml:"-"`
	Retain   *bool      `yaml:"-"`
	UID      uint32     `yaml:"uid,omitempty"`
	GID      uint32     `yaml:"gid,omitempty"`
	Mode     string     `yaml:"mode,omitempty"`
	Capacity VolumeSize `yaml:"size,omitempty"`
	Quota    string     `yaml:"-"`
	Backup   *struct {
		Consistency string `yaml:"consistency"`
		Retain      int    `yaml:"retain_artifacts"`
	} `yaml:"-"`
	Migration *struct {
		Mode   string `yaml:"mode"`
		Fence  bool   `yaml:"require_source_fence"`
		Retain bool   `yaml:"retain_source"`
	} `yaml:"-"`
}
type ComposeSecret struct {
	File     string `yaml:"file,omitempty"`
	Name     string `yaml:"name,omitempty"`
	External bool   `yaml:"external,omitempty"`
	MyDC     struct {
		// Source is service-final-keyset for a secret with neither file
		// nor external (normalize); app.yaml gives only the key.
		Source string `yaml:"-"`
		Key    string `yaml:"key,omitempty"`
	} `yaml:"x-mydc,omitempty"`
}
type AppExtension struct {
	Lifecycle *LifecycleDeclaration `yaml:"lifecycle,omitempty" json:",omitempty"`
	// Schema, Tenant and Deployment are set by the server (the request's
	// tenant, the app name); app.yaml has no keys for them.
	Schema     uint8  `yaml:"-"`
	Tenant     string `yaml:"-"`
	Deployment string `yaml:"-"`
	Nodes      map[string]struct {
		Underlay string `yaml:"underlay"`
		Voter    bool   `yaml:"voter"`
	} `yaml:"nodes,omitempty"`
	Ingress  *IngressDeclaration  `yaml:"ingress,omitempty"`
	Vault    *VaultDeclaration    `yaml:"vault,omitempty"`
	Delivery *DeliveryDeclaration `yaml:"delivery,omitempty"`
	Routing  *struct {
		Default string             `yaml:"cross_tenant_default"`
		Routes  []RouteDeclaration `yaml:"routes"`
	} `yaml:"routing,omitempty"`
	Registries map[string]RegistryDeclaration `yaml:"registries,omitempty"`
}
type IngressDeclaration struct {
	Node      string                    `yaml:"node"`
	Runtime   IngressRuntime            `yaml:"runtime"`
	Host      string                    `yaml:"host"`
	Gateway   string                    `yaml:"gateway,omitempty" json:",omitempty"`
	Balance   *ingress.Balance          `yaml:"balance,omitempty" json:",omitempty"`
	Routes    []IngressRouteDeclaration `yaml:"routes,omitempty" json:",omitempty"`
	Listeners []ListenerDeclaration     `yaml:"listeners"`
	Backend   struct {
		Service    string `yaml:"service"`
		Network    string `yaml:"network,omitempty"`
		Port       uint16 `yaml:"port"`
		HealthPath string `yaml:"health_path"`
	} `yaml:"backend"`
}
type IngressRouteDeclaration struct {
	ID         string           `yaml:"id,omitempty"`
	Host       string           `yaml:"host"`
	Prefix     string           `yaml:"prefix,omitempty"`
	Service    string           `yaml:"service"`
	Network    string           `yaml:"network,omitempty"`
	Port       uint16           `yaml:"port,omitempty"`
	HealthPath string           `yaml:"health_path,omitempty"`
	Gateway    string           `yaml:"gateway,omitempty"`
	Balance    *ingress.Balance `yaml:"balance,omitempty"`
}

// IngressRuntime is explicit per-application demand; node/tenant limits are
// separate committed ceilings. No listener capacity comes from an empty root.
type IngressRuntime struct {
	MaxRequests             int   `yaml:"max_requests"`
	MaxConnections          int   `yaml:"max_connections"`
	MaxHeaderBytes          int   `yaml:"max_header_bytes"`
	MaxBodyBytes            int64 `yaml:"max_body_bytes"`
	BufferBytes             int   `yaml:"buffer_bytes"`
	RequestTimeoutMS        int   `yaml:"request_timeout_ms"`
	DialTimeoutMS           int   `yaml:"dial_timeout_ms"`
	ResponseHeaderTimeoutMS int   `yaml:"response_header_timeout_ms"`
	HealthIntervalMS        int   `yaml:"health_interval_ms"`
}
type ListenerDeclaration struct {
	Shared  string `yaml:"shared,omitempty" json:",omitempty"`
	Address string `yaml:"address"`
	// TLS serves HTTPS; each host's certificate comes from the cluster store.
	TLS   bool `yaml:"tls,omitempty" json:",omitempty"`
	HTTP3 bool `yaml:"http3,omitempty"`
}
type VaultDeclaration struct {
	Mode string `yaml:"mode"`
	Tree struct {
		Root struct {
			Entries []Selector `yaml:"entries"`
		} `yaml:"root"`
		Groups  map[string]GroupDeclaration  `yaml:"groups"`
		Secrets map[string]SecretDeclaration `yaml:"secrets"`
	} `yaml:"tree"`
	Approval struct {
		Prompt  string   `yaml:"prompt"`
		Reuse   string   `yaml:"reuse"`
		Payload []string `yaml:"signed_payload_fields"`
	} `yaml:"approval"`
}
type GroupDeclaration struct {
	ID        string     `yaml:"id"`
	Parent    string     `yaml:"parent"`
	Protected bool       `yaml:"password_required"`
	Services  []string   `yaml:"allowed_services,omitempty"`
	Entries   []Selector `yaml:"entries"`
}
type SecretDeclaration struct {
	ID       string   `yaml:"id"`
	Parent   string   `yaml:"parent"`
	Profile  string   `yaml:"provider_profile"`
	Object   string   `yaml:"object"`
	Revision uint64   `yaml:"revision"`
	Keys     []string `yaml:"keys"`
}
type DeliveryDeclaration struct {
	Enabled bool `yaml:"enabled"`
	Source  struct {
		Kind       string `yaml:"kind"`
		Repository string `yaml:"repository"`
		Ref        string `yaml:"ref"`
		Path       string `yaml:"path"`
		Credential string `yaml:"credential_profile,omitempty"`
	} `yaml:"source"`
	Poll uint64 `yaml:"poll_interval_seconds"`
	Sync struct {
		Mode       string `yaml:"mode"`
		Drift      string `yaml:"drift"`
		Prune      bool   `yaml:"prune"`
		AllowEmpty bool   `yaml:"allow_empty"`
	} `yaml:"sync"`
	Runtime struct {
		Mode   string `yaml:"mode"`
		Expiry string `yaml:"expiry"`
	} `yaml:"runtime_edits"`
	Limits struct {
		Fetch  uint64 `yaml:"fetch_timeout_seconds"`
		Bytes  uint64 `yaml:"source_bytes"`
		Queued uint64 `yaml:"queued_revisions"`
		Active uint64 `yaml:"active_operations"`
	} `yaml:"limits"`
}
type RouteDeclaration struct {
	ID                 string   `yaml:"id"`
	SourceTenant       string   `yaml:"source_tenant"`
	SourceNetwork      string   `yaml:"source_network"`
	DestinationTenant  string   `yaml:"destination_tenant"`
	DestinationNetwork string   `yaml:"destination_network"`
	Protocol           string   `yaml:"protocol"`
	Ports              []uint16 `yaml:"ports"`
	Approvals          []string `yaml:"approval_refs"`
}
type RegistryDeclaration struct {
	Enabled  bool   `yaml:"enabled"`
	Node     string `yaml:"node"`
	Image    string `yaml:"image"`
	Network  string `yaml:"network"`
	IPv4     string `yaml:"ipv4_address"`
	Port     uint16 `yaml:"container_port"`
	Volume   string `yaml:"volume"`
	Listener struct {
		Address     string `yaml:"address"`
		Host        string `yaml:"host"`
		Certificate string `yaml:"certificate"`
	} `yaml:"listener"`
	Auth struct {
		Mode      string `yaml:"mode"`
		Issuer    string `yaml:"issuer"`
		Anonymous bool   `yaml:"anonymous"`
		MaxToken  uint64 `yaml:"max_token_seconds"`
	} `yaml:"auth"`
	Trusted   bool `yaml:"register_as_trusted"`
	Resources struct {
		CPUs   string `yaml:"cpus"`
		Memory uint64 `yaml:"memory_bytes"`
	} `yaml:"resources"`
}
