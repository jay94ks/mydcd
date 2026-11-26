// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/compose-spec/compose-go/v2/loader"
	ct "github.com/compose-spec/compose-go/v2/types"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/workload"
	"gopkg.in/yaml.v3"
)

func nodeField(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
func fieldsOnly(n *yaml.Node, shape any) error {
	if n == nil || n.Tag == "!!null" {
		return nil
	}
	if n.Kind != yaml.MappingNode {
		return inputError("MAPPING_REQUIRED", "document")
	}
	allowed := map[string]bool{}
	t := reflect.TypeOf(shape)
	for i := 0; i < t.NumField(); i++ {
		name := strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0]
		if name != "" && name != "-" {
			allowed[name] = true
		}
	}
	for i := 0; i < len(n.Content); i += 2 {
		if !allowed[n.Content[i].Value] {
			return inputError("UNSUPPORTED_FIELD", n.Content[i].Value)
		}
	}
	return nil
}
func extension(n *yaml.Node, out any) error {
	if x := nodeField(n, "x-mydc"); x != nil {
		return strictNode(x, out)
	}
	return nil
}

// Compose's wider language is narrowed BEFORE the library loader can resolve
// paths, environment, include/extends or extensions. These are MyDC admission
// rules; union conversion and the standard model belong to compose-go.
func composeSubset(root *yaml.Node) error {
	if err := lifecycleSubset(root); err != nil {
		return err
	}
	if err := fieldsOnly(root, Compose{}); err != nil {
		return err
	}
	for _, section := range []struct {
		name  string
		shape any
	}{{"networks", ComposeNetwork{}}, {"volumes", ComposeVolume{}}, {"secrets", ComposeSecret{}}} {
		n := nodeField(root, section.name)
		if n == nil {
			continue
		}
		if n.Kind != yaml.MappingNode {
			return ErrInputs
		}
		for i := 1; i < len(n.Content); i += 2 {
			if err := fieldsOnly(n.Content[i], section.shape); err != nil {
				return err
			}
			if x := nodeField(n.Content[i], "external"); x != nil && x.Tag != "!!bool" {
				return inputError("BOOLEAN_EXTERNAL_REQUIRED", section.name)
			}
		}
	}
	services := nodeField(root, "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return inputError("SERVICES_REQUIRED", "services")
	}
	for i := 1; i < len(services.Content); i += 2 {
		n := services.Content[i]
		if err := fieldsOnly(n, ComposeService{}); err != nil {
			return err
		}
		if ports := nodeField(n, "ports"); ports != nil {
			if ports.Kind != yaml.SequenceNode {
				return inputError("INVALID_PUBLISHED_PORTS", "ports")
			}
			for _, port := range ports.Content {
				if port.Kind == yaml.MappingNode {
					if err := fieldsOnly(port, workload.PublishedPort{}); err != nil {
						return err
					}
				}
			}
		}
		if log := nodeField(n, "logging"); log != nil {
			if log.Kind != yaml.MappingNode || fieldsOnly(log, workload.LogPolicy{}) != nil {
				return inputError("INVALID_LOGGING_POLICY", "logging")
			}
			if driver := nodeField(log, "driver"); driver == nil || driver.Tag != "!!str" {
				return inputError("INVALID_LOGGING_POLICY", "logging.driver")
			}
			if options := nodeField(log, "options"); options != nil {
				if options.Kind != yaml.MappingNode {
					return inputError("INVALID_LOGGING_POLICY", "logging.options")
				}
				for j := 0; j < len(options.Content); j += 2 {
					if options.Content[j].Tag != "!!str" || options.Content[j+1].Tag != "!!str" {
						return inputError("STRING_LOGGING_OPTIONS_REQUIRED", "logging.options")
					}
				}
			}
		}
		for _, name := range []string{"stop_grace_period", "stop_signal"} {
			if value := nodeField(n, name); value != nil && (value.Kind != yaml.ScalarNode || value.Tag != "!!str" || value.Value == "") {
				return inputError("INVALID_STOP_POLICY", name)
			}
		}
		for _, name := range []string{"command", "entrypoint"} {
			if v := nodeField(n, name); v != nil {
				if v.Kind != yaml.SequenceNode {
					return inputError("EXEC_FORM_REQUIRED", name)
				}
				for _, a := range v.Content {
					if a.Tag != "!!str" {
						return inputError("EXEC_FORM_REQUIRED", name)
					}
				}
			}
		}
		if env := nodeField(n, "environment"); env != nil {
			seen := map[string]bool{}
			switch env.Kind {
			case yaml.MappingNode:
				for j := 1; j < len(env.Content); j += 2 {
					v := env.Content[j]
					if v.Kind != yaml.ScalarNode || v.Tag == "!!null" || v.Tag == "!!bool" {
						return inputError("EXPLICIT_ENV_REQUIRED", "environment")
					}
				}
			case yaml.SequenceNode:
				for _, v := range env.Content {
					key, _, ok := strings.Cut(v.Value, "=")
					if v.Tag != "!!str" || !ok || seen[key] {
						return inputError("EXPLICIT_ENV_REQUIRED", "environment")
					}
					seen[key] = true
				}
			default:
				return inputError("EXPLICIT_ENV_REQUIRED", "environment")
			}
		}
		if dep := nodeField(n, "depends_on"); dep != nil {
			if dep.Kind == yaml.MappingNode {
				for j := 1; j < len(dep.Content); j += 2 {
					if err := fieldsOnly(dep.Content[j], ServiceDependency{}); err != nil {
						return err
					}
				}
			} else if dep.Kind == yaml.SequenceNode {
				seen := map[string]bool{}
				for _, v := range dep.Content {
					if v.Tag != "!!str" || seen[v.Value] {
						return ErrInputs
					}
					seen[v.Value] = true
				}
			} else {
				return ErrInputs
			}
		}
		if nets := nodeField(n, "networks"); nets != nil {
			if nets.Kind != yaml.MappingNode {
				return inputError("EXPLICIT_ATTACHMENTS_REQUIRED", "networks")
			}
			for j := 1; j < len(nets.Content); j += 2 {
				if err := fieldsOnly(nets.Content[j], Attachment{}); err != nil {
					return err
				}
			}
		}
		if h := nodeField(n, "healthcheck"); h != nil {
			if err := fieldsOnly(h, Healthcheck{}); err != nil {
				return err
			}
			if disable := nodeField(h, "disable"); disable != nil && disable.Tag != "!!bool" {
				return inputError("BOOLEAN_HEALTHCHECK_DISABLE_REQUIRED", "healthcheck.disable")
			}
		}
		for _, mounts := range []struct {
			name  string
			shape any
		}{{"volumes", Mount{}}, {"secrets", SecretMount{}}} {
			v := nodeField(n, mounts.name)
			if v == nil {
				continue
			}
			if v.Kind != yaml.SequenceNode {
				return ErrInputs
			}
			for _, entry := range v.Content {
				if entry.Kind == yaml.MappingNode {
					if err := fieldsOnly(entry, mounts.shape); err != nil {
						return err
					}
				} else if entry.Tag != "!!str" {
					return ErrInputs
				} else if mounts.name == "volumes" {
					parts := strings.Split(entry.Value, ":")
					if len(parts) < 2 || len(parts) > 3 || len(parts) == 3 && parts[2] != "ro" && parts[2] != "rw" {
						return inputError("NAMED_VOLUME_REQUIRED", "volumes")
					}
				}
			}
		}
	}
	return nil
}

func standardCompose(raw []byte) (*ct.Project, error) {
	var model map[string]any
	if yaml.Unmarshal(raw, &model) != nil {
		return nil, ErrInputs
	}
	// A secret with neither file nor external is MyDC's final keyset, supplied by its Vault owner, outside Compose's
	// file/environment source model. Project it as an external reference ONLY
	// in the standard model, then restore the original MyDC declaration below.
	// This neither grants access nor claims an external Docker secret exists.
	if definitions, ok := model["secrets"].(map[string]any); ok {
		for _, entry := range definitions {
			definition, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if definition["file"] == nil && definition["environment"] == nil && definition["external"] != true {
				definition["external"] = true
			}
		}
	}
	return loader.LoadWithContext(context.Background(), ct.ConfigDetails{WorkingDir: "/", ConfigFiles: []ct.ConfigFile{{Filename: "mydc-compose.yaml", Config: model}}, Environment: ct.Mapping{}}, func(o *loader.Options) {
		o.SetProjectName("mydc", true)
		o.SkipInterpolation = true
		o.SkipInclude = true
		o.SkipExtends = true
		o.SkipResolveEnvironment = true
		o.SkipResolveLabels = true
		o.ResolvePaths = false
		o.ConvertWindowsPaths = false
		o.SkipNormalization = true
		o.SkipDefaultValues = true
		o.SkipConsistencyCheck = true
		o.MaxNodeVisits = 65536
	})
}
func loadCompose(raw []byte, root *yaml.Node, standalone ...bool) (Compose, error) {
	if err := composeSubset(root); err != nil {
		return Compose{}, err
	}
	project, err := standardCompose(raw)
	if err != nil {
		return Compose{}, inputError("INVALID_COMPOSE", "document")
	}
	c := Compose{Standalone: len(standalone) == 1 && standalone[0], Services: map[string]ComposeService{}}
	if n := nodeField(root, "name"); n != nil {
		c.Name = n.Value
	}
	if err = extension(root, &c.MyDC); err != nil {
		return Compose{}, err
	}
	for name, s := range project.Services {
		n := nodeField(nodeField(root, "services"), name)
		v := ComposeService{Standalone: c.Standalone, WorkingDir: s.WorkingDir, TTY: s.Tty, StdinOpen: s.StdinOpen, Image: s.Image, User: s.User, CapDrop: s.CapDrop, SecurityOpt: s.SecurityOpt, Tmpfs: []string(s.Tmpfs)}
		for _, port := range s.Ports {
			v.Ports = append(v.Ports, workload.PublishedPort{Name: port.Name, HostIP: port.HostIP, Target: port.Target, Published: port.Published, Protocol: port.Protocol, Mode: port.Mode, AppProtocol: port.AppProtocol})
		}
		v.Ports, err = workload.NormalizePublishedPorts(v.Ports)
		if err != nil {
			return Compose{}, inputError("INVALID_PUBLISHED_PORTS", "services."+name+".ports")
		}

		if declared := nodeField(n, "logging"); declared != nil {
			v.Logging = new(workload.LogPolicy)
			if strictNode(declared, v.Logging) != nil || v.Logging.Validate() != nil {
				return Compose{}, inputError("INVALID_LOGGING_POLICY", "services."+name+".logging")
			}
		}
		if nodeField(n, "stop_grace_period") != nil {
			if s.StopGracePeriod == nil {
				return Compose{}, inputError("INVALID_STOP_POLICY", "stop_grace_period")
			}
			v.StopGracePeriod = time.Duration(*s.StopGracePeriod).String()
		}
		if nodeField(n, "stop_signal") != nil {
			var err error
			v.StopSignal, err = engine.NormalizeStopSignal(s.StopSignal)
			if err != nil || v.StopSignal == "" {
				return Compose{}, inputError("INVALID_STOP_POLICY", "stop_signal")
			}
		}
		if nodeField(n, "dns") != nil {
			v.DNS = make([]string, len(s.DNS))
			copy(v.DNS, s.DNS)
		}
		if nodeField(n, "dns_search") != nil {
			v.DNSSearch = make([]string, len(s.DNSSearch))
			copy(v.DNSSearch, s.DNSSearch)
		}
		if nodeField(n, "command") != nil {
			a := make(Arguments, len(s.Command))
			copy(a, s.Command)
			v.Command = &a
		}
		if nodeField(n, "entrypoint") != nil {
			a := make(Arguments, len(s.Entrypoint))
			copy(a, s.Entrypoint)
			v.Entrypoint = &a
		}
		if nodeField(n, "read_only") != nil {
			v.ReadOnly = &s.ReadOnly
		}
		if cpus := nodeField(n, "cpus"); cpus != nil {
			v.CPUs = cpus.Value
		} // retain exact decimal budget, not library float32 rounding.
		if nodeField(n, "mem_limit") != nil {
			v.Memory = fmt.Sprint(int64(s.MemLimit))
		}
		if nodeField(n, "environment") != nil {
			v.Environment = Environment{}
			for k, value := range s.Environment {
				if value == nil {
					return Compose{}, ErrInputs
				}
				v.Environment[k] = *value
			}
		}
		if s.DependsOn != nil {
			v.DependsOn = Dependencies{}
			for k, d := range s.DependsOn {
				v.DependsOn[k] = ServiceDependency{d.Condition}
			}
		}
		if s.Networks != nil {
			v.Networks = map[string]Attachment{}
			for k, a := range s.Networks {
				if a == nil {
					v.Networks[k] = Attachment{}
				} else {
					v.Networks[k] = Attachment{IPv4: a.Ipv4Address, IPv6: a.Ipv6Address, Aliases: append([]string(nil), a.Aliases...)}
				}
			}
		}
		for _, m := range s.Volumes {
			v.Volumes = append(v.Volumes, Mount{m.Type, m.Source, m.Target, m.ReadOnly})
		}
		for _, m := range s.Secrets {
			mode := ""
			if m.Mode != nil {
				mode = m.Mode.String()
			}
			v.Secrets = append(v.Secrets, SecretMount{m.Source, m.Target, m.UID, m.GID, mode})
		}
		if h := s.HealthCheck; h != nil {
			v.Healthcheck = &Healthcheck{Test: []string(h.Test)}
			if h.Disable {
				v.Healthcheck.Test = []string{"NONE"}
			}
			if h.Retries != nil {
				if *h.Retries > 1000 {
					return Compose{}, ErrInputs
				}
				v.Healthcheck.Retries = int(*h.Retries)
			}
			for _, d := range []struct {
				name   string
				target *string
			}{{"interval", &v.Healthcheck.Interval}, {"timeout", &v.Healthcheck.Timeout}, {"start_period", &v.Healthcheck.StartPeriod}, {"start_interval", &v.Healthcheck.StartInterval}} {
				if value := nodeField(nodeField(n, "healthcheck"), d.name); value != nil {
					*d.target = value.Value
				}
			}
		}
		if err = extension(n, &v.MyDC); err != nil {
			return Compose{}, err
		}
		c.Services[name] = v
	}
	if nodeField(root, "networks") != nil {
		c.Networks = map[string]ComposeNetwork{}
	}
	for name, n := range project.Networks {
		v := ComposeNetwork{Name: n.Name, External: bool(n.External), Driver: n.Driver}
		if err = extension(nodeField(nodeField(root, "networks"), name), &v.MyDC); err != nil {
			return Compose{}, err
		}
		c.Networks[name] = v
	}
	if nodeField(root, "volumes") != nil {
		c.Volumes = map[string]ComposeVolume{}
	}
	for name, s := range project.Volumes {
		v := ComposeVolume{Name: s.Name, External: bool(s.External), Driver: s.Driver}
		if err = extension(nodeField(nodeField(root, "volumes"), name), &v.MyDC); err != nil {
			return Compose{}, err
		}
		c.Volumes[name] = v
	}
	if nodeField(root, "secrets") != nil {
		c.Secrets = map[string]ComposeSecret{}
	}
	for name, s := range project.Secrets {
		v := ComposeSecret{Name: s.Name, File: s.File, External: bool(s.External)}
		rawDefinition := nodeField(nodeField(root, "secrets"), name)
		if err = extension(rawDefinition, &v.MyDC); err != nil {
			return Compose{}, err
		}
		if nodeField(rawDefinition, "file") == nil {
			v.External = false
			if original := nodeField(rawDefinition, "external"); original != nil {
				if err = original.Decode(&v.External); err != nil {
					return Compose{}, ErrInputs
				}
			}
		}
		c.Secrets[name] = v
	}
	if err = c.normalize(); err != nil {
		return Compose{}, err
	}
	return c, nil
}
