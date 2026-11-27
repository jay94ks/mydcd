// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/reconcile"
	bolt "go.etcd.io/bbolt"
)

type RootUse uint8

const (
	JobRoot RootUse = iota + 1
	CacheRoot
)

// Presence is the original borrow intent. The returned lease is fixed before
// any workspace/native effect. Returning survives a lost Return/DB response.
type NativeRootHold struct {
	Lease               reconcile.Lease
	Returning, Returned bool
}

func (h NativeRootHold) validate(generation uint64) error {
	if h.Lease.Token == 0 && h.Lease.Generation != 0 || h.Lease.Token != 0 && h.Lease.Generation != generation || h.Returned && !h.Returning {
		return ErrStorage
	}
	return nil
}

func (n *NativeJobs) RootConsumer(spec JobSpec, use RootUse) (string, error) {
	p, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return "", err
	}
	switch use {
	case JobRoot:
		return "imagebuild/job/" + hex.EncodeToString(p.Job[:]), nil
	case CacheRoot:
		return "imagebuild/cache/" + hex.EncodeToString(p.Cache[:]), nil
	}
	return "", ErrInvalid
}

// Caller holds n.mu. All root transitions reuse the original native job or
// cache record in this same DB, rather than a parallel execution journal.
func (n *NativeJobs) editRoot(spec JobSpec, use RootUse, edit func(NativeRecord, *nativeCacheBorrow, **NativeRootHold) error) error {
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	switch use {
	case JobRoot:
		if err := edit(r, nil, &r.Root); err != nil {
			return err
		}
		return n.save(r)
	case CacheRoot:
		p, err := PlanNative(spec, n.docker.Owner)
		if err != nil {
			return err
		}
		return n.db.Update(func(tx *bolt.Tx) error {
			c, err := readNativeCache(tx, spec, p)
			if err != nil {
				return err
			}
			if err := edit(r, &c, &c.RootHold); err != nil {
				return err
			}
			if c.RootHold != nil && c.RootHold.validate(spec.Scope.Root.Generation) != nil {
				return ErrStorage
			}
			raw, err := json.Marshal(c)
			if err != nil {
				return ErrStorage
			}
			return tx.Bucket(nativeBucket).Put(nativeCacheKey(p.Cache), raw)
		})
	}
	return ErrInvalid
}

func (n *NativeJobs) RootHold(spec JobSpec, use RootUse) (NativeRootHold, bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return NativeRootHold{}, false, err
	}
	h := r.Root
	if use == CacheRoot {
		p, err := PlanNative(spec, n.docker.Owner)
		if err != nil {
			return NativeRootHold{}, false, err
		}
		err = n.db.View(func(tx *bolt.Tx) error { c, err := readNativeCache(tx, spec, p); h = c.RootHold; return err })
		if err != nil {
			return NativeRootHold{}, false, err
		}
	} else if use != JobRoot {
		return NativeRootHold{}, false, ErrInvalid
	}
	if h == nil {
		return NativeRootHold{}, false, nil
	}
	return *h, true, nil
}

func (n *NativeJobs) PlanRootHold(ctx context.Context, spec JobSpec, use RootUse) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	g, err := n.current(ctx, &r, true)
	if err != nil {
		return err
	}
	return n.editRoot(spec, use, func(r NativeRecord, c *nativeCacheBorrow, h **NativeRootHold) error {
		if c != nil && c.Retirement != nil {
			return ErrUsed
		}
		if *h != nil {
			if (*h).Returning || (*h).Returned {
				return ErrUsed
			}
			return nil
		}
		if !g.Allowed || g.Run.Cancel || g.Run.Phase != "queued" || r.Cancel || r.CreateSent || r.Completion != nil {
			return ErrConflict
		}
		*h = &NativeRootHold{}
		return nil
	})
}

// Binding is recovery of the original borrow acknowledgement, not a new
// permission check or permission to substitute another generation/token.
func (n *NativeJobs) BindRootHold(spec JobSpec, use RootUse, lease reconcile.Lease) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if lease.Token == 0 || lease.Generation != spec.Scope.Root.Generation {
		return ErrInvalid
	}
	return n.editRoot(spec, use, func(r NativeRecord, c *nativeCacheBorrow, h **NativeRootHold) error {
		if c != nil && c.Retirement != nil {
			return ErrUsed
		}
		if *h == nil || (*h).Returning || (*h).Returned || r.Completion != nil {
			return ErrConflict
		}
		if (*h).Lease.Token != 0 && (*h).Lease != lease {
			return ErrStorage
		}
		(*h).Lease = lease
		return nil
	})
}

func (n *NativeJobs) BeginRootReturn(spec JobSpec, use RootUse) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.readers[spec.Digest()] != 0 || n.publishing[spec.Digest()] {
		return ErrUsed
	}
	return n.editRoot(spec, use, func(r NativeRecord, c *nativeCacheBorrow, h **NativeRootHold) error {
		if *h == nil {
			return ErrConflict
		}
		if c != nil {
			// Cache byte deletion/settlement is a separate owner operation.
			// A normal job completion never returns the retained cache root.
			if c.Owner != ([32]byte{}) || c.Directory.valid() {
				return ErrUsed
			}
		} else if !nativeEffectsClosed(r) {
			return ErrUsed
		}
		(*h).Returning = true
		return nil
	})
}

func (n *NativeJobs) FinishRootReturn(spec JobSpec, use RootUse) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.editRoot(spec, use, func(_ NativeRecord, _ *nativeCacheBorrow, h **NativeRootHold) error {
		if *h == nil || !(*h).Returning {
			return ErrConflict
		}
		(*h).Returned = true
		return nil
	})
}

func sameNativeCache(a, b nativeCacheBorrow) bool {
	if a.Schema != b.Schema || a.Root != b.Root || a.Cache != b.Cache || a.Owner != b.Owner || a.Directory != b.Directory {
		return false
	}
	if a.Retirement == nil || b.Retirement == nil {
		if a.Retirement != b.Retirement {
			return false
		}
	} else if *a.Retirement != *b.Retirement {
		return false
	}
	if a.RootHold == nil || b.RootHold == nil {
		return a.RootHold == nil && b.RootHold == nil
	}
	return *a.RootHold == *b.RootHold
}
