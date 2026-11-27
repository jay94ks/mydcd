// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

var ErrInputMount = errors.New("invalid or unavailable original task input mount")

// InputRef is public metadata. Host paths and fetched values are node-local.
type InputRef struct {
	Key        string
	Generation uint64
	Binding    [32]byte
}
type InputFile struct {
	Source, Target string
	UID, GID, Mode uint32
	Kind           string
	Reference      string // Public winning Secret/key identity, never a value.
}
type InputLease struct {
	Ref   InputRef
	Pin   reconcile.Lease
	Files []InputFile
}

func (InputLease) MarshalJSON() ([]byte, error) { return nil, ErrInputMount }
func (InputFile) MarshalJSON() ([]byte, error)  { return nil, ErrInputMount }
func (InputLease) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted task input lease]")
}
func (InputFile) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[redacted task input file]") }

// Acquisition is a current activation gate. Inspection/removal keep the exact
// previously synced consumer pin even after permission revocation or Drain.
type InputProvider interface {
	AcquireInputs(context.Context, InputRef, string, string, uint64) (InputLease, error)
	InspectInputs(context.Context, InputRef, string, string, uint64) (InputLease, error)
	RetiringInputs(context.Context, InputRef, string, string, uint64) (InputLease, error)
	ReturnInputs(InputRef, string, string, uint64) error
}

func (d *DockerDriver) inputLease(ctx context.Context, s ContainerSpec, id engine.Identity, key string, generation uint64, mode string) (InputLease, error) {
	if s.Inputs == nil {
		return InputLease{}, nil
	}
	if d.Inputs == nil {
		return InputLease{}, ErrInputMount
	}
	var l InputLease
	var err error
	switch mode {
	case "acquire":
		l, err = d.Inputs.AcquireInputs(ctx, *s.Inputs, containerConsumer(id), key, generation)
	case "retire":
		l, err = d.Inputs.RetiringInputs(ctx, *s.Inputs, containerConsumer(id), key, generation)
	default:
		l, err = d.Inputs.InspectInputs(ctx, *s.Inputs, containerConsumer(id), key, generation)
	}
	if err != nil {
		return InputLease{}, err
	}
	if l.Ref != *s.Inputs || l.Pin.Generation != s.Inputs.Generation || l.Pin.Token == 0 || len(l.Files) > 256 {
		return InputLease{}, ErrInputMount
	}
	for i, f := range l.Files {
		if !filepath.IsAbs(f.Source) || filepath.Clean(f.Source) != f.Source || strings.ContainsAny(f.Source, "\x00\r\n") || !validInputDelivery(f) {
			return InputLease{}, ErrInputMount
		}
		for _, p := range l.Files[:i] {
			if (p.Kind == "env") == (f.Kind == "env") && OverlappingMounts(p.Target, f.Target) {
				return InputLease{}, ErrInputMount
			}
		}
	}
	return l, nil
}
func inputMounts(files []InputFile) []mount.Mount {
	var mounts []mount.Mount
	for _, f := range files {
		if f.Kind == "env" {
			continue
		}
		mounts = append(mounts, mount.Mount{Type: mount.TypeBind, Source: f.Source, Target: f.Target, ReadOnly: true, BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate, NonRecursive: true}})
	}
	return mounts
}
func matchInputMounts(got container.InspectResponse, files []InputFile) bool {
	files = mountedInputFiles(files)
	// HostConfig.Tmpfs is independently matched. Those mounts are not in
	// Engine MountPoints; any unrequested bind/volume/typed tmpfs is foreign.
	if len(got.Mounts) != len(files) || got.HostConfig == nil || len(got.HostConfig.Mounts) != len(files) {
		return false
	}
	for _, f := range files {
		found := false
		for _, m := range got.Mounts {
			if m.Destination == f.Target {
				if m.Type != mount.TypeBind || m.Source != f.Source || m.RW {
					return false
				}
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
