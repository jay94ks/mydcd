// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/containerops"
)

type ContainerExecRecord struct {
	Schema   uint8
	Profile  [32]byte
	Original access.Session
	Intent   containerops.SessionIntent
}
type containerExecRecord ContainerExecRecord

func (ContainerExecRecord) MarshalJSON() ([]byte, error) { return nil, ErrPrivateState }
func (ContainerExecRecord) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted container exec intent]")
}

func containerExecRoot(home string, c Client, user string, create bool) (*os.Root, error) {
	if !safeID(user) {
		return nil, ErrPrivateState
	}
	r, err := profileRootID(home, c.Cluster, c.JournalProfile(), create)
	if err != nil {
		if !create && errors.Is(err, os.ErrNotExist) {
			return nil, ErrOperationMissing
		}
		return nil, err
	}
	for _, name := range []string{"container-execs", user} {
		if !create {
			if _, err = r.Lstat(name); os.IsNotExist(err) {
				_ = r.Close()
				return nil, ErrOperationMissing
			}
		}
		next, err := descend(r, name, create)
		_ = r.Close()
		if err != nil {
			return nil, err
		}
		r = next
	}
	return r, nil
}

func containerExecName(tenant, app, operation string) string {
	return operationName(tenant + "/" + app + "/" + operation)
}

func readContainerExec(root *os.Root, c Client, current access.Session, tenant, app, operation string) (ContainerExecRecord, error) {
	var row containerExecRecord
	if !safeID(tenant) || !safeID(app) || !safeID(operation) {
		return ContainerExecRecord{}, ErrPrivateState
	}
	name := containerExecName(tenant, app, operation)
	if _, err := root.Lstat(name); os.IsNotExist(err) {
		return ContainerExecRecord{}, ErrOperationMissing
	}
	if readPrivateLimit(root, name, &row, 128<<10) != nil || row.Schema != 1 || row.Profile != c.JournalProfile() || row.Intent.User != current.User || row.Original.User != current.User || row.Intent.Request != operation || row.Intent.Target.Cluster != c.Cluster || row.Intent.Target.Tenant != tenant || row.Intent.Target.App != app || row.Intent.Spec.Kind != "exec" || row.Intent.Verify(row.Original.Key) != nil || access.VerifyOriginalSession(row.Original, c.Cluster, row.Intent.At) != nil || access.ExactSessionDigest(row.Original) != row.Intent.Session {
		return ContainerExecRecord{}, ErrPrivateState
	}
	return ContainerExecRecord(row), nil
}

func LoadContainerExec(home string, c Client, current access.Session, tenant, app, operation string) (ContainerExecRecord, error) {
	if c.Verify(current) != nil {
		return ContainerExecRecord{}, ErrPrivateState
	}
	r, err := containerExecRoot(home, c, current.User, false)
	if err != nil {
		return ContainerExecRecord{}, err
	}
	defer r.Close()
	return readContainerExec(r, c, current, tenant, app, operation)
}

func StageContainerExec(home string, c Client, current access.Session, intent containerops.SessionIntent) (ContainerExecRecord, error) {
	if c.Verify(current) != nil || intent.Verify(current.Key) != nil || intent.User != current.User || intent.Session != access.ExactSessionDigest(current) || intent.Target.Cluster != c.Cluster || intent.Spec.Kind != "exec" {
		return ContainerExecRecord{}, ErrPrivateState
	}
	r, err := containerExecRoot(home, c, current.User, true)
	if err != nil {
		return ContainerExecRecord{}, err
	}
	defer r.Close()
	unlock, err := lockProfile(r)
	if err != nil {
		return ContainerExecRecord{}, err
	}
	defer unlock()
	old, err := readContainerExec(r, c, current, intent.Target.Tenant, intent.Target.App, intent.Request)
	if err == nil {
		if old.Intent.Digest() != intent.Digest() {
			return ContainerExecRecord{}, ErrPrivateState
		}
		return old, nil
	}
	if !errors.Is(err, ErrOperationMissing) {
		return ContainerExecRecord{}, err
	}
	dir, err := r.Open(".")
	if err != nil {
		return ContainerExecRecord{}, err
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return ContainerExecRecord{}, err
	}
	count := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			count++
		}
	}
	if count >= operationLimit {
		return ContainerExecRecord{}, ErrPrivateState
	}
	row := ContainerExecRecord{Schema: 1, Profile: c.JournalProfile(), Original: current, Intent: intent}
	if err = writePrivateLimit(r, containerExecName(intent.Target.Tenant, intent.Target.App, intent.Request), containerExecRecord(row), 128<<10); err != nil {
		return ContainerExecRecord{}, err
	}
	return row, nil
}
