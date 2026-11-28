// SPDX-License-Identifier: Apache-2.0

package app

import "github.com/jay94ks/seafield/internal/sfcp"

// startTopics attaches the SFCP Topic channel (purpose 26) to the mesh,
// once, before the mesh listens. Each feature only reserves its family on
// it: obs (observation_topics.go), later alm.
func (r *Runtime) startTopics() error {
	t, err := sfcp.NewTopics(r.Mesh)
	if err != nil {
		return err
	}
	r.topics = t
	return nil
}

// Topics is this node's side of the Topic channel; nil before the mesh
// exists.
func (r *Runtime) Topics() *sfcp.Topics { return r.topics }
