// SPDX-License-Identifier: Apache-2.0

// Command featurenotes prints the feature-set table for a release
// announcement (Jay 2026-11-28 08:35 KST: every release lists its feature
// set changes and version ranges in a table). It reads this build's
// buildinfo.Own; with -prev it also compares against the previous release's
// announced names (its FEATURES.txt, one name per line) and fills the change
// column.
//
//	go run ./tools/featurenotes [-prev old/FEATURES.txt] [-list]
//
// -list prints this build's names one per line instead (the FEATURES.txt a
// release attaches for the next one to compare against).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/buildinfo"
)

func main() {
	prev := flag.String("prev", "", "previous release's FEATURES.txt")
	list := flag.Bool("list", false, "print this build's feature names, one per line")
	flag.Parse()
	if *list {
		for _, n := range buildinfo.Own.Names() {
			fmt.Println(n)
		}
		return
	}
	var old *buildinfo.Features
	if *prev != "" {
		f, err := os.Open(*prev)
		if err != nil {
			fmt.Fprintln(os.Stderr, "featurenotes:", err)
			os.Exit(1)
		}
		s, err := readNames(f)
		f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "featurenotes:", *prev+":", err)
			os.Exit(1)
		}
		old = &s
	}
	fmt.Print(table(buildinfo.Own, old))
}

func readNames(r io.Reader) (buildinfo.Features, error) {
	var list []buildinfo.Feature
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		n := strings.TrimSpace(sc.Text())
		if n == "" || strings.HasPrefix(n, "#") {
			continue
		}
		f, ok := buildinfo.ParseFeature(n)
		if !ok {
			return buildinfo.Features{}, fmt.Errorf("unknown feature %q", n)
		}
		list = append(list, f)
	}
	if err := sc.Err(); err != nil {
		return buildinfo.Features{}, err
	}
	s, ok := buildinfo.NewFeatures(list...)
	if !ok {
		return buildinfo.Features{}, fmt.Errorf("not a valid feature set")
	}
	return s, nil
}

// setInfo is one feature set as a build announces it.
type setInfo struct {
	min, max uint16   // mainline range, 0 when none
	other    []string // postfixed versions, written vN-postfix
}

func sets(s buildinfo.Features) map[[2]uint8]*setInfo {
	out := map[[2]uint8]*setInfo{}
	for _, f := range s.List() {
		k := [2]uint8{f.Group, f.Set}
		i := out[k]
		if i == nil {
			i = &setInfo{}
			out[k] = i
		}
		switch {
		case !f.Stable():
			i.other = append(i.other, fmt.Sprintf("v%d-%s", f.Version, f.Postfix))
		case i.min == 0:
			i.min, i.max = f.Version, f.Version
		default:
			i.max = f.Version
		}
	}
	return out
}

func (i *setInfo) rangeText() string {
	switch {
	case i == nil || i.min == 0:
		return "—"
	case i.min == i.max:
		return fmt.Sprintf("v%d", i.min)
	}
	return fmt.Sprintf("v%d–v%d", i.min, i.max)
}

func (i *setInfo) otherText() string {
	if i == nil || len(i.other) == 0 {
		return "—"
	}
	return strings.Join(i.other, ", ")
}

// change describes the step from o (previous release) to n (this build).
func change(o, n *setInfo) string {
	switch {
	case o == nil && n == nil:
		return "—"
	case o == nil:
		return "새 기능 집합"
	case n == nil:
		return "빠짐"
	}
	var parts []string
	if n.max > o.max {
		parts = append(parts, fmt.Sprintf("v%d 추가", n.max))
	}
	if n.min > o.min && o.min != 0 {
		parts = append(parts, fmt.Sprintf("최소 v%d로 올림", n.min))
	}
	if n.max < o.max || n.min == 0 && o.min != 0 {
		parts = append(parts, "mainline 버전 줄어듦")
	}
	for _, p := range n.other {
		if !slices.Contains(o.other, p) {
			parts = append(parts, p+" 추가")
		}
	}
	for _, p := range o.other {
		if !slices.Contains(n.other, p) {
			parts = append(parts, p+" 빠짐")
		}
	}
	if len(parts) == 0 {
		return "변화 없음"
	}
	return strings.Join(parts, ", ")
}

func table(own buildinfo.Features, prev *buildinfo.Features) string {
	now := sets(own)
	var before map[[2]uint8]*setInfo
	keys := map[[2]uint8]bool{}
	for k := range now {
		keys[k] = true
	}
	if prev != nil {
		before = sets(*prev)
		for k := range before {
			keys[k] = true
		}
	}
	order := make([][2]uint8, 0, len(keys))
	for k := range keys {
		order = append(order, k)
	}
	slices.SortFunc(order, func(a, b [2]uint8) int {
		return int(a[0])<<8 | int(a[1]) - (int(b[0])<<8 | int(b[1]))
	})
	var b strings.Builder
	fmt.Fprintf(&b, "### 기능 집합 (major %d)\n\n", buildinfo.Major)
	if len(order) == 0 {
		fmt.Fprintf(&b, "이 빌드는 major %d의 기본 기능만 씁니다. 추가 기능 집합이 없습니다.\n", buildinfo.Major)
		return b.String()
	}
	if prev != nil {
		b.WriteString("| 그룹 | 기능 집합 | 지원 버전 범위 | 시험 버전 | 이전 릴리스 | 변화 |\n|---|---|---|---|---|---|\n")
	} else {
		b.WriteString("| 그룹 | 기능 집합 | 지원 버전 범위 | 시험 버전 |\n|---|---|---|---|\n")
	}
	for _, k := range order {
		n := now[k]
		fmt.Fprintf(&b, "| %s | %s | %s | %s |", buildinfo.GroupName(k[0]), buildinfo.SetName(k[0], k[1]), n.rangeText(), n.otherText())
		if prev != nil {
			o := before[k]
			fmt.Fprintf(&b, " %s | %s |", o.rangeText(), change(o, n))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n지원 버전 범위 안의 mainline 버전은 같은 major의 다른 빌드와 호환됩니다. 시험 버전(접미사가 붙은 버전)은 양쪽이 똑같은 버전을 알릴 때만 쓰고, 다음 빌드에서 바뀌거나 빠질 수 있습니다.\n")
	return b.String()
}
