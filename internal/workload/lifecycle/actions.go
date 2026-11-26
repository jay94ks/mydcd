// SPDX-License-Identifier: Apache-2.0

package lifecycle

import contract "github.com/jay94ks/mydcd/lifecycle/v1"

// ContainerAction is chosen by MyDC from a check result and the current
// Docker state. Scripts return observations; they do not receive this control
// interface or a Docker socket.
type ContainerAction string

const (
	KeepContainer    ContainerAction = "keep"
	StartContainer   ContainerAction = "start"
	StopContainer    ContainerAction = "stop"
	RestartContainer ContainerAction = "restart"
)

type ActionPolicy struct {
	OnAlive ContainerAction `yaml:"on_alive,omitempty" json:"on_alive,omitempty"`
	OnDead  ContainerAction `yaml:"on_dead,omitempty" json:"on_dead,omitempty"`
}

func (p ActionPolicy) Validate() error {
	for _, action := range []ContainerAction{p.OnAlive, p.OnDead} {
		if action != "" && action != KeepContainer && action != StartContainer && action != StopContainer && action != RestartContainer {
			return ErrContract
		}
	}
	return nil
}

// Decide never treats an unknown observation as dead. The caller must still
// check the original Task and current desired state before a Docker effect.
func (p ActionPolicy) Decide(status contract.Status, running bool) (ContainerAction, error) {
	if p.Validate() != nil || !validStatus(status) {
		return KeepContainer, ErrContract
	}
	if status == contract.Unknown {
		return KeepContainer, nil
	}
	action := p.OnAlive
	if status == contract.Fail {
		action = p.OnDead
	}
	if action == "" || action == StartContainer && running || action == StopContainer && !running {
		return KeepContainer, nil
	}
	if action == RestartContainer && !running {
		return StartContainer, nil
	}
	return action, nil
}

func validCheckActions(scope string, phase contract.Phase, actions *ActionPolicy) bool {
	return actions == nil || scope != "" && phase == contract.Liveness && actions.Validate() == nil
}
