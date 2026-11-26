// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
)

type RequestEvent struct {
	At                                                                     uint64 // milliseconds, supplied by the actual HTTP adapter
	Method, Host, Path, Route, Backend, Failure, Block, Gateway, Condition string
	Status                                                                 int
	DurationMS, ReceivedBytes, SentBytes                                   uint64
	Source                                                                 netip.Addr
}
type ErrorSample struct {
	At                                                  uint64
	Method, Host, Path, Backend, Failure, Block, Source string
	Status                                              int
	DurationMS                                          uint64
}
type Metric struct {
	OpenConnections                             uint64
	ID                                          string
	Requests, Blocked, ReceivedBytes, SentBytes uint64
	Rate                                        float64
	Responses                                   [4]uint64 // 2xx, 3xx, 4xx, 5xx
	P50MS, P95MS, P99MS                         uint64
	Failures                                    map[string]uint64 `json:",omitempty"`
}
type Metrics struct {
	ConnectionKind                         string `json:",omitempty"`
	WindowSeconds                          uint64
	Instance                               Metric
	Routes, Backends, Gateways, Conditions []Metric
	Errors                                 []ErrorSample
}
type metricBucket struct {
	Second                            uint64
	Requests, Blocked, Received, Sent uint64
	Responses                         [4]uint64
	Latency                           [24]uint64
	Failures                          map[string]uint64
}
type metricSeries struct {
	buckets [60]metricBucket
	last    uint64
	live    uint64
}
type requestMetrics struct {
	instance                               metricSeries
	routes, backends, gateways, conditions map[string]*metricSeries
	errors                                 []ErrorSample
}

func safePublic(s string, limit int) string {
	if len(s) > limit {
		s = s[:limit]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
}
func (m *Management) Record(key string, e RequestEvent) {
	if key == "" || e.At == 0 || e.Status < 0 || e.Status > 599 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.metrics[key]
	if r == nil {
		r = &requestMetrics{routes: map[string]*metricSeries{}, backends: map[string]*metricSeries{}, gateways: map[string]*metricSeries{}, conditions: map[string]*metricSeries{}}
		m.metrics[key] = r
	}
	add := func(s *metricSeries) {
		second := e.At / 1000
		if second > s.last {
			s.last = second
		}
		b := &s.buckets[second%60]
		if b.Second != second {
			*b = metricBucket{Second: second, Failures: map[string]uint64{}}
		}
		b.Requests++
		if e.Block != "" {
			b.Blocked++
		}
		b.Received += e.ReceivedBytes
		b.Sent += e.SentBytes
		if e.Status >= 200 {
			at := e.Status/100 - 2
			if at >= 0 && at < 4 {
				b.Responses[at]++
			}
		}
		latency := 0
		for latency < 23 && e.DurationMS > uint64(1)<<latency {
			latency++
		}
		b.Latency[latency]++
		if e.Failure != "" && len(b.Failures) < 32 {
			b.Failures[safePublic(e.Failure, 64)]++
		}
	}
	add(&r.instance)
	for _, entry := range []struct {
		id     string
		values map[string]*metricSeries
		limit  int
	}{{e.Route, r.routes, 256}, {e.Backend, r.backends, 1024}, {e.Gateway, r.gateways, 2}, {e.Condition, r.conditions, 256}} {
		if entry.id == "" {
			continue
		}
		s := entry.values[entry.id]
		if s == nil {
			for id, old := range entry.values {
				second := e.At / 1000
				if second >= old.last && second-old.last >= 60 && old.live == 0 {
					delete(entry.values, id)
				}
			}
		}
		if s == nil && len(entry.values) < entry.limit {
			s = &metricSeries{}
			entry.values[entry.id] = s
		}
		if s != nil {
			add(s)
		}
	}
	if e.Status >= 400 || e.Block != "" || e.Failure != "" {
		source := ""
		if e.Source.IsValid() {
			addr := e.Source.Unmap()
			bits := 48
			if addr.Is4() {
				bits = 24
			}
			source = netip.PrefixFrom(addr, bits).Masked().String()
		}
		path, _, _ := strings.Cut(e.Path, "?")
		sample := ErrorSample{At: e.At, Method: safePublic(e.Method, 32), Host: safePublic(e.Host, 253), Path: safePublic(path, 2048), Backend: safePublic(e.Backend, 512), Failure: safePublic(e.Failure, 64), Block: e.Block, Source: source, Status: e.Status, DurationMS: e.DurationMS}
		if len(r.errors) == 200 {
			copy(r.errors, r.errors[1:])
			r.errors[199] = sample
		} else {
			r.errors = append(r.errors, sample)
		}
	}
}
func metricSnapshot(id string, s *metricSeries, now uint64) Metric {
	out := Metric{ID: id, OpenConnections: s.live, Failures: map[string]uint64{}}
	var histogram [24]uint64
	for _, b := range s.buckets {
		if b.Second > now || now-b.Second >= 60 {
			continue
		}
		out.Requests += b.Requests
		out.Blocked += b.Blocked
		out.ReceivedBytes += b.Received
		out.SentBytes += b.Sent
		for i, n := range b.Responses {
			out.Responses[i] += n
		}
		for i, n := range b.Latency {
			histogram[i] += n
		}
		for k, n := range b.Failures {
			out.Failures[k] += n
		}
	}
	out.Rate = float64(out.Requests) / 60
	percentile := func(percent uint64) uint64 {
		if out.Requests == 0 {
			return 0
		}
		rank := (out.Requests*percent + 99) / 100
		var n uint64
		for i, count := range histogram {
			n += count
			if n >= rank {
				return uint64(1) << i
			}
		}
		return 1 << 23
	}
	out.P50MS, out.P95MS, out.P99MS = percentile(50), percentile(95), percentile(99)
	return out
}
func (m *Management) Snapshot(key string, nowMS uint64) Metrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := Metrics{WindowSeconds: 60, ConnectionKind: "upstream-live"}
	r := m.metrics[key]
	if r == nil {
		return out
	}
	now := nowMS / 1000
	out.Instance = metricSnapshot(key, &r.instance, now)
	for id, s := range r.routes {
		out.Routes = append(out.Routes, metricSnapshot(id, s, now))
	}
	for id, s := range r.backends {
		out.Backends = append(out.Backends, metricSnapshot(id, s, now))
	}
	for id, s := range r.gateways {
		out.Gateways = append(out.Gateways, metricSnapshot(id, s, now))
	}
	for id, s := range r.conditions {
		out.Conditions = append(out.Conditions, metricSnapshot(id, s, now))
	}
	slices.SortFunc(out.Gateways, func(a, b Metric) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(out.Conditions, func(a, b Metric) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(out.Routes, func(a, b Metric) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(out.Backends, func(a, b Metric) int { return strings.Compare(a.ID, b.ID) })
	out.Errors = slices.Clone(r.errors)
	return out
}

// ForgetMetrics releases only local request instrumentation after the actual
// instance has gone. Replicated block history and application facts survive.
func (m *Management) ForgetMetrics(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.metrics, key)
}

// ConnectionOpened consumes an actual successful upstream Dial. The returned
// release is fixed to that series lifetime: an old Close cannot decrement a new
// instance reusing the same key. It is not an HTTP request/client count.
func (m *Management) ConnectionOpened(key, route, backend string) func() {
	if key == "" {
		return func() {}
	}
	m.mu.Lock()
	r := m.metrics[key]
	if r == nil {
		r = &requestMetrics{routes: map[string]*metricSeries{}, backends: map[string]*metricSeries{}, gateways: map[string]*metricSeries{}, conditions: map[string]*metricSeries{}}
		m.metrics[key] = r
	}
	series := []*metricSeries{&r.instance}
	for _, entry := range []struct {
		id     string
		values map[string]*metricSeries
		limit  int
	}{{route, r.routes, 256}, {backend, r.backends, 1024}} {
		if entry.id == "" {
			continue
		}
		s := entry.values[entry.id]
		if s == nil && len(entry.values) < entry.limit {
			s = &metricSeries{}
			entry.values[entry.id] = s
		}
		if s != nil {
			series = append(series, s)
		}
	}
	for _, s := range series {
		if s.live < ^uint64(0) {
			s.live++
		}
	}
	m.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.metrics[key] != r {
				return
			}
			for _, s := range series {
				if s.live > 0 {
					s.live--
				}
			}
		})
	}
}
