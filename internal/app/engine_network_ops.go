// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"net/netip"
	"os"

	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// Purpose 36 EngineNetwork: the engine's built-in sfc network driver asks
// at create, created, join, leave and delete. The structs mirror the
// engine's field for field (seafield/docs/sfcd-socket.md, "op 구조체");
// the answers are network.EngineHooks (devel/design/engine-network-hook.md).

type engineNetworkIPAM struct {
	Subnet, Gateway string
}

type engineNetworkCreate struct {
	engineops.Request
	NetworkID, Name string
	Labels, Options map[string]string
	IPAM            []engineNetworkIPAM
}

type engineNetworkCreateReply struct {
	engineops.Reply
	Bridge string
	MTU    int
}

type engineNetworkCreated struct {
	engineops.Request
	NetworkID, Name string
	Labels          map[string]string
	Bridge          string
	MTU             int
	Gateway         []string
}

type engineNetworkDelete struct {
	engineops.Request
	NetworkID, Name string
	Labels          map[string]string
}

type engineNetworkJoin struct {
	engineops.Request
	NetworkID, Endpoint, ContainerID, ContainerName string
	ContainerLabels                                 map[string]string
	Addresses                                       []string
	MAC, SandboxKey, HostVeth                       string
}

type engineNetworkRoute struct {
	Destination, NextHop string
}

type engineNetworkJoinReply struct {
	engineops.Reply
	Allow   bool
	MTU     int
	Routes  []engineNetworkRoute
	Sysctls map[string]string
}

type engineNetworkLeave struct {
	engineops.Request
	NetworkID, Endpoint, ContainerID string
	Addresses                        []string
}

type engineNetworkEmptyReply struct {
	engineops.Reply
}

func (r *Runtime) engineNetworkOps() []engineops.Entry {
	return []engineops.Entry{
		engineops.Op[engineNetworkCreate, engineNetworkCreateReply](engineops.Network, "create", r.engineNetworkCreate),
		engineops.Op[engineNetworkCreated, engineNetworkEmptyReply](engineops.Network, "created", r.engineNetworkCreated),
		engineops.Op[engineNetworkJoin, engineNetworkJoinReply](engineops.Network, "join", r.engineNetworkJoin),
		engineops.Op[engineNetworkLeave, engineNetworkEmptyReply](engineops.Network, "leave", r.engineNetworkLeave),
		engineops.Op[engineNetworkDelete, engineNetworkEmptyReply](engineops.Network, "delete", r.engineNetworkDelete),
	}
}

func engineEnvelope(q engineops.Request) network.EngineEnvelope {
	return network.EngineEnvelope{OpID: q.OpID, BootID: q.BootID}
}

// engineAnswer turns a hook answer into the table's error: nil for applied,
// a refusal for not-applied, anything else for unknown.
func engineAnswer(a network.EngineAnswer) error {
	switch a.Result {
	case network.EngineApplied:
		return nil
	case network.EngineNotApplied:
		return engineops.Refuse(a.Code, nil)
	}
	return errors.New("engine network answer unknown")
}

var errEngineNetworkOff = engineops.Refuse(engineops.NotReady, errors.New("network module is off"))

func (r *Runtime) engineNetworkCreate(_ context.Context, q engineNetworkCreate) (engineNetworkCreateReply, []*os.File, error) {
	if r.engineNetwork == nil {
		return engineNetworkCreateReply{}, nil, errEngineNetworkOff
	}
	in := network.EngineCreate{EngineEnvelope: engineEnvelope(q.Request), ID: q.NetworkID, Name: q.Name, Labels: q.Labels, Options: q.Options}
	for _, p := range q.IPAM {
		subnet, err1 := netip.ParsePrefix(p.Subnet)
		gateway, err2 := engineGateway(p.Gateway)
		if err1 != nil || err2 != nil {
			return engineNetworkCreateReply{}, nil, engineops.Refuse(engineops.Invalid, errors.Join(err1, err2))
		}
		in.IPAM = append(in.IPAM, network.EngineIPAM{Subnet: subnet, Gateway: gateway})
	}
	a := r.engineNetwork.Create(in)
	if err := engineAnswer(a); err != nil {
		return engineNetworkCreateReply{}, nil, err
	}
	return engineNetworkCreateReply{Bridge: a.Bridge, MTU: a.MTU}, nil, nil
}

// engineGateway reads a gateway as libnetwork prints it: the address with
// its pool's mask ("10.254.0.1/16", from a *net.IPNet), or a bare address.
func engineGateway(s string) (netip.Addr, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

func (r *Runtime) engineNetworkCreated(_ context.Context, q engineNetworkCreated) (engineNetworkEmptyReply, []*os.File, error) {
	if r.engineNetwork == nil {
		return engineNetworkEmptyReply{}, nil, errEngineNetworkOff
	}
	in := network.EngineCreated{EngineEnvelope: engineEnvelope(q.Request), ID: q.NetworkID, Name: q.Name, Labels: q.Labels, Bridge: q.Bridge, MTU: q.MTU}
	for _, g := range q.Gateway {
		a, err := engineGateway(g)
		if err != nil {
			return engineNetworkEmptyReply{}, nil, engineops.Refuse(engineops.Invalid, err)
		}
		in.Gateway = append(in.Gateway, a)
	}
	return engineNetworkEmptyReply{}, nil, engineAnswer(r.engineNetwork.Created(in))
}

func (r *Runtime) engineNetworkJoin(_ context.Context, q engineNetworkJoin) (engineNetworkJoinReply, []*os.File, error) {
	if r.engineNetwork == nil {
		return engineNetworkJoinReply{}, nil, errEngineNetworkOff
	}
	in := network.EngineJoin{EngineEnvelope: engineEnvelope(q.Request), ID: q.NetworkID, Endpoint: q.Endpoint, ContainerID: q.ContainerID, ContainerName: q.ContainerName, ContainerLabels: q.ContainerLabels, MAC: q.MAC, SandboxKey: q.SandboxKey, HostVeth: q.HostVeth}
	for _, s := range q.Addresses {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return engineNetworkJoinReply{}, nil, engineops.Refuse(engineops.Invalid, err)
		}
		in.Addresses = append(in.Addresses, p)
	}
	a := r.engineNetwork.Join(in)
	if err := engineAnswer(a); err != nil {
		return engineNetworkJoinReply{}, nil, err
	}
	out := engineNetworkJoinReply{Allow: a.Allow, MTU: a.MTU, Routes: []engineNetworkRoute{}, Sysctls: map[string]string{}}
	for _, route := range a.Routes {
		out.Routes = append(out.Routes, engineNetworkRoute{Destination: route.Destination.String(), NextHop: route.NextHop.String()})
	}
	for k, v := range a.Sysctls {
		out.Sysctls[k] = v
	}
	return out, nil, nil
}

func (r *Runtime) engineNetworkLeave(_ context.Context, q engineNetworkLeave) (engineNetworkEmptyReply, []*os.File, error) {
	if r.engineNetwork == nil {
		return engineNetworkEmptyReply{}, nil, errEngineNetworkOff
	}
	return engineNetworkEmptyReply{}, nil, engineAnswer(r.engineNetwork.Leave(network.EngineLeave{EngineEnvelope: engineEnvelope(q.Request), ID: q.NetworkID, Endpoint: q.Endpoint, ContainerID: q.ContainerID}))
}

func (r *Runtime) engineNetworkDelete(_ context.Context, q engineNetworkDelete) (engineNetworkEmptyReply, []*os.File, error) {
	if r.engineNetwork == nil {
		return engineNetworkEmptyReply{}, nil, errEngineNetworkOff
	}
	return engineNetworkEmptyReply{}, nil, engineAnswer(r.engineNetwork.Delete(network.EngineDelete{EngineEnvelope: engineEnvelope(q.Request), ID: q.NetworkID, Name: q.Name, Labels: q.Labels}))
}

// engineNetworkAdmit: a container joins a Bridge only with a lease on it.
// Task containers borrow as workload/<container name>; cluster app
// containers as cluster-app/<app>/<generation>.
func (r *Runtime) engineNetworkAdmit(q network.EngineAdmit) error {
	if r.network == nil {
		return errors.New("network module is off")
	}
	// The system bridge carries only cluster apps, and the cluster-app
	// journal alone says which container and address may join it.
	if r.installation != nil && q.Key == (tenancy.SourceIdentity{Kind: "bridge", Network: tenancy.SystemNetwork, Node: r.installation.record.Root.Self.ID}).Key() {
		if allow, handled := r.clusterAppJoin(q.NetworkID, q.ContainerID, q.ContainerName, q.Labels, q.Addresses); handled && allow {
			return nil
		}
		return errors.New("only the cluster app the journal holds joins the system bridge")
	}
	record, err := r.network.View(q.Key)
	if err != nil {
		return err
	}
	if pin, ok := record.Consumers["workload/"+q.ContainerName]; ok && pin.Generation == q.Generation {
		return nil
	}
	return errors.New("container holds no lease on this Bridge")
}
