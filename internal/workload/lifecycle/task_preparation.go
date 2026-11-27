// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

const preparationPrefix = sourcePrefix + "task-preparation/"
const MaxTaskPreparationBytes = 384 << 10
const maxPreparationBytes = 32 << 20

var ErrPreparation = errors.New("original lifecycle task preparation unavailable or changed")

type TaskPreparation struct {
	Schema                            uint8
	Cluster, Owner, Use, Program, SDK [32]byte
	Tenant, UseID, Target             string
	DeadlineUnixMilli                 int64
	Plan                              *TaskCompilePlan `json:",omitempty"`
}
type TaskCompilePlan struct {
	Recipes []CompileRecipe
	Build   *BuildIntent `json:",omitempty"`
}

func CompileSDKDigest() [32]byte { _, hash := fileManifest(trustedCompileSources()); return hash }
func TaskCompileID(clusterID, use [32]byte) string {
	raw, _ := json.Marshal(struct {
		Schema       uint8
		Cluster, Use [32]byte
	}{1, clusterID, use})
	hash := sha256.Sum256(append([]byte("sfc-checker-task-preparation-1\x00"), raw...))
	return hex.EncodeToString(hash[:])
}
func (p TaskPreparation) ID() string { return TaskCompileID(p.Cluster, p.Use) }
func (p TaskPreparation) Clone() TaskPreparation {
	if p.Plan != nil {
		plan := *p.Plan
		plan.Recipes = slices.Clone(plan.Recipes)
		for i := range plan.Recipes {
			plan.Recipes[i].Flags = slices.Clone(plan.Recipes[i].Flags)
		}
		if plan.Build != nil {
			b := plan.Build.Clone()
			plan.Build = &b
		}
		p.Plan = &plan
	}
	return p
}
func (p TaskPreparation) Digest() [32]byte { raw, _ := json.Marshal(p); return sha256.Sum256(raw) }
func (p TaskPreparation) Validate() error {
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > MaxTaskPreparationBytes || p.Schema != 1 || p.Cluster == ([32]byte{}) || p.Owner == ([32]byte{}) || p.Use == ([32]byte{}) || p.Program == ([32]byte{}) || p.SDK == ([32]byte{}) || !name(p.Tenant) || !name(p.UseID) || p.DeadlineUnixMilli <= 0 || p.Target != "linux/amd64" && p.Target != "linux/arm64" {
		return ErrPreparation
	}
	if p.Plan == nil {
		return nil
	}
	if len(p.Plan.Recipes) == 0 || len(p.Plan.Recipes) > MaxScripts {
		return ErrPreparation
	}
	for i, r := range p.Plan.Recipes {
		if r.Validate() != nil || r.Tenant != p.Tenant || r.SDK != p.SDK || r.GOOS+"/"+r.GOARCH != p.Target || i > 0 && bytes.Compare(p.Plan.Recipes[i-1].Source[:], r.Source[:]) >= 0 {
			return ErrPreparation
		}
	}
	if b := p.Plan.Build; b != nil {
		if b.Validate() != nil || b.Cluster != p.Cluster || b.Tenant != p.Tenant || b.ID != p.ID() || b.AppUseID != p.UseID || b.AppUse != p.Use || b.Target != p.Target || b.DeadlineUnixMilli != p.DeadlineUnixMilli {
			return ErrPreparation
		}
		for _, input := range b.Inputs {
			if !slices.ContainsFunc(p.Plan.Recipes, func(r CompileRecipe) bool { return r.Source == input.Content && r.Key() == input.Recipe }) {
				return ErrPreparation
			}
		}
	}
	return nil
}
func preparationKey(p TaskPreparation) string { return p.Tenant + "/" + p.ID() }
func (m *SourceStore) loadPreparations() error {
	rows, err := m.db.SizesBounded(preparationPrefix, maxSourceEntries, maxSourceEntries*256)
	if err != nil {
		return err
	}
	index := map[string][32]byte{}
	var total uint64
	for key, size := range rows {
		if size == 0 || size > MaxTaskPreparationBytes || total > maxPreparationBytes || size > maxPreparationBytes-total {
			return ErrPreparation
		}
		raw, err := m.db.GetBounded(key, MaxTaskPreparationBytes)
		if err != nil {
			return err
		}
		p, err := schema.Decode[TaskPreparation](raw)
		if err != nil || p.Validate() != nil || p.Cluster != m.identity.Cluster || p.Owner != m.identity.Node || key != preparationPrefix+preparationKey(p) {
			return ErrPreparation
		}
		index[preparationKey(p)], total = p.Digest(), total+size
	}
	// Recovery may observe exactly the pending seal or its prior draft. It
	// cannot erase a known original or adopt an unrelated valid replacement.
	for key, old := range m.preparations {
		actual, ok := index[key]
		if !ok || actual != old && actual != m.preparationWrites[key] {
			return ErrPreparation
		}
	}
	m.preparations, m.preparationBytes = index, total
	m.preparationWrites = nil
	return nil
}
func (m *SourceStore) readPreparation(tenant, id string) (TaskPreparation, error) {
	key := tenant + "/" + id
	raw, err := m.db.GetBounded(preparationPrefix+key, MaxTaskPreparationBytes)
	known, ok := m.preparations[key]
	if err != nil {
		if ok {
			return TaskPreparation{}, errors.Join(ErrPreparation, err)
		}
		return TaskPreparation{}, err
	}
	p, err := schema.Decode[TaskPreparation](raw)
	if err != nil || !ok || p.Validate() != nil || p.Cluster != m.identity.Cluster || p.Owner != m.identity.Node || preparationKey(p) != key || p.Digest() != known {
		return TaskPreparation{}, ErrPreparation
	}
	return p, nil
}
func (m *SourceStore) TaskPreparation(ctx context.Context, tenant, id string, recover bool) (TaskPreparation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || !name(tenant) || !digest(id) || m.closed {
		return TaskPreparation{}, ErrPreparation
	}
	if recover {
		if err := m.recover(); err != nil {
			return TaskPreparation{}, err
		}
		m.uncertain = false
	} else if m.uncertain {
		return TaskPreparation{}, ErrSourceUncertain
	}
	return m.readPreparation(tenant, id)
}
func (m *SourceStore) savePreparation(p TaskPreparation, old *TaskPreparation) error {
	raw, err := json.Marshal(p)
	if err != nil || p.Validate() != nil {
		return ErrPreparation
	}
	var previous uint64
	if old != nil {
		before, _ := json.Marshal(old)
		previous = uint64(len(before))
	}
	usage, err := m.cacheUsage(p.Tenant)
	if err != nil {
		return err
	}
	if previous > m.preparationBytes || previous > usage.preparation || usage.preparation-previous > maxPreparationBytes || uint64(len(raw)) > maxPreparationBytes-(usage.preparation-previous) || old == nil && usage.preparations >= maxSourceEntries {
		return ErrPreparation
	}
	if err := m.db.Write(map[string][]byte{preparationPrefix + preparationKey(p): raw}); err != nil {
		m.uncertain = true
		if m.preparationWrites == nil {
			m.preparationWrites = map[string][32]byte{}
		}
		m.preparationWrites[preparationKey(p)] = p.Digest()
		return errors.Join(ErrSourceUncertain, err)
	}
	m.preparations[preparationKey(p)] = p.Digest()
	m.preparationBytes = m.preparationBytes - previous + uint64(len(raw))
	return nil
}

// Begin fixes the original deadline before source/cache work. An existing
// original scope wins; later attempts cannot reset deadline or SDK/target.
func (m *SourceStore) BeginTaskPreparation(ctx context.Context, p TaskPreparation) (TaskPreparation, error) {
	p = p.Clone()
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || m.closed || m.uncertain || p.Validate() != nil || p.Plan != nil || p.Cluster != m.identity.Cluster || p.Owner != m.identity.Node {
		return TaskPreparation{}, ErrPreparation
	}
	old, err := m.readPreparation(p.Tenant, p.ID())
	if err == nil {
		want, actual := p, old
		want.DeadlineUnixMilli = actual.DeadlineUnixMilli
		actual.Plan = nil
		if want.Digest() != actual.Digest() {
			return TaskPreparation{}, ErrPreparation
		}
		return old.Clone(), nil
	}
	if !errors.Is(err, storage.ErrMissing) || errors.Is(err, ErrPreparation) {
		return TaskPreparation{}, err
	}
	if err := m.savePreparation(p, nil); err != nil {
		return TaskPreparation{}, err
	}
	return p.Clone(), nil
}

// Seal publishes exactly one complete plan BEFORE any shared reserve report.
// A concurrent sealed original wins rather than receiving a replacement job.
func (m *SourceStore) SealTaskPreparation(ctx context.Context, p TaskPreparation) (TaskPreparation, error) {
	p = p.Clone()
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || m.closed || m.uncertain || p.Validate() != nil || p.Plan == nil || p.Cluster != m.identity.Cluster || p.Owner != m.identity.Node {
		return TaskPreparation{}, ErrPreparation
	}
	old, err := m.readPreparation(p.Tenant, p.ID())
	if err != nil {
		return TaskPreparation{}, err
	}
	want, actual := p, old
	want.Plan = nil
	actual.Plan = nil
	if want.Digest() != actual.Digest() {
		return TaskPreparation{}, ErrPreparation
	}
	if old.Plan != nil {
		return old.Clone(), nil
	}
	if err := m.savePreparation(p, &old); err != nil {
		return TaskPreparation{}, err
	}
	return p.Clone(), nil
}
