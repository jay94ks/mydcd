// SPDX-License-Identifier: Apache-2.0

package firewall

// only is a server firewall under an untouched cluster firewall.
func only(s State) Layers { return Layers{Node: s, Cluster: NewCluster()} }

func ref(l Layers) *Layers { return &l }
