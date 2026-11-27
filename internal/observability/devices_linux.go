// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// ErrDevicesBusy: the previous inventory has not returned yet (a device
// read can hang on a failing disk). The next round tries again.
var ErrDevicesBusy = errors.New("device inventory still running")

const deviceProbeBytes = 0x11000

type deviceSources struct {
	Sys, Dev, MountInfo, Swaps string
	Space                      func(path string) *BlockSpace
}

var inventory struct {
	sync.Mutex
	running bool
}

// InspectDevices lists the server's block devices. It reads sysfs, the
// host mount table, /proc/swaps and the first 68 KiB of each device; it
// never writes to a device. A read that hangs leaves this round without an
// inventory, never the rest of the observation loop.
func InspectDevices(ctx context.Context) (Devices, error) {
	inventory.Lock()
	if inventory.running {
		inventory.Unlock()
		return Devices{}, ErrDevicesBusy
	}
	inventory.running = true
	inventory.Unlock()
	type result struct {
		d   Devices
		err error
	}
	done := make(chan result, 1)
	go func() {
		d, err := inspectDevices(deviceSources{Sys: "/sys", Dev: "/dev", MountInfo: "/proc/self/mountinfo", Swaps: "/proc/swaps", Space: statSpace})
		inventory.Lock()
		inventory.running = false
		inventory.Unlock()
		done <- result{d, err}
	}()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.d, r.err
	case <-ctx.Done():
		return Devices{}, ctx.Err()
	case <-timer.C:
		return Devices{}, ErrDevicesBusy
	}
}

func statSpace(path string) *BlockSpace {
	var fs unix.Statfs_t
	if unix.Statfs(path, &fs) != nil || fs.Bsize <= 0 || fs.Blocks == 0 || fs.Bfree > fs.Blocks || fs.Bavail > fs.Bfree || fs.Blocks > ^uint64(0)/uint64(fs.Bsize) {
		return nil
	}
	unit := uint64(fs.Bsize)
	total, free := fs.Blocks*unit, fs.Bfree*unit
	return &BlockSpace{Total: total, Used: total - free, Available: min(fs.Bavail*unit, free)}
}

type blockMount struct{ point, kind string }

// Mounts that are runtime internals, not where an operator put a disk.
var hiddenMountPrefixes = []string{"/proc/", "/sys/", "/dev/", "/run/docker/", "/run/sfe/", "/run/netns/", "/var/lib/docker/", "/var/lib/sfe/", "/snap/"}

func readBlockMounts(r io.Reader) (map[string][]blockMount, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), 1<<20)
	decode := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	out := map[string][]blockMount{}
	for s.Scan() {
		parts := strings.SplitN(s.Text(), " - ", 2)
		if len(parts) != 2 {
			return nil, ErrReport
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 6 || len(right) < 2 {
			return nil, ErrReport
		}
		point := decode.Replace(left[4])
		hidden := false
		for _, prefix := range hiddenMountPrefixes {
			hidden = hidden || strings.HasPrefix(point+"/", prefix)
		}
		key := left[2]
		if strings.HasPrefix(key, "0:") {
			// Btrfs reports an anonymous device number; its source names
			// the real device. Anything else on 0: is tmpfs, overlay or proc.
			source := decode.Replace(right[1])
			if right[0] != "btrfs" || !strings.HasPrefix(source, "/dev/") {
				continue
			}
			if resolved, e := filepath.EvalSymlinks(source); e == nil {
				source = resolved
			}
			key = "name:" + filepath.Base(source)
		}
		if !hidden {
			out[key] = append(out[key], blockMount{point: point, kind: right[0]})
		}
	}
	return out, s.Err()
}

func readSwaps(path, dev string) map[string]bool {
	out := map[string]bool{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for i, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if i == 0 || len(fields) < 2 || fields[1] != "partition" {
			continue
		}
		name := strings.ReplaceAll(fields[0], `\040`, " ")
		if resolved, e := filepath.EvalSymlinks(name); e == nil {
			name = resolved
		}
		if filepath.Dir(name) == filepath.Clean(dev) {
			out[filepath.Base(name)] = true
		}
	}
	return out
}

func sysText(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 4096 {
		return ""
	}
	s := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(string(raw)))
	s = strings.TrimSpace(s)
	if len(s) > maxDeviceText {
		s = s[:maxDeviceText]
	}
	return strings.ToValidUTF8(s, "")
}

func sysNumber(path string) uint64 {
	n, _ := strconv.ParseUint(sysText(path), 10, 64)
	return n
}

func firstText(paths ...string) string {
	for _, p := range paths {
		if s := sysText(p); s != "" {
			return s
		}
	}
	return ""
}

var skippedDisks = []string{"loop", "ram", "zram", "sr", "fd", "dm-", "md", "nbd"}

func inspectDevices(src deviceSources) (Devices, error) {
	f, err := os.Open(src.MountInfo)
	if err != nil {
		return Devices{}, err
	}
	mounts, err := readBlockMounts(io.LimitReader(f, 16<<20))
	f.Close()
	if err != nil {
		return Devices{}, err
	}
	swaps := readSwaps(src.Swaps, src.Dev)
	entries, err := os.ReadDir(filepath.Join(src.Sys, "block"))
	if err != nil {
		return Devices{}, err
	}
	out := Devices{}
	for _, entry := range entries {
		name := entry.Name()
		skip := !deviceName(name)
		for _, prefix := range skippedDisks {
			skip = skip || strings.HasPrefix(name, prefix)
		}
		dir := filepath.Join(src.Sys, "block", name)
		size := sysNumber(filepath.Join(dir, "size")) * 512
		if skip || size == 0 {
			continue
		}
		if len(out.Disks) == maxBlockDisks {
			out.Truncated = true
			break
		}
		out.Disks = append(out.Disks, inspectDisk(src, name, dir, size, mounts, swaps))
	}
	slices.SortFunc(out.Disks, func(a, b BlockDisk) int { return strings.Compare(a.Name, b.Name) })
	for !out.valid() && len(out.Disks) > 0 {
		out.Disks, out.Truncated = out.Disks[:len(out.Disks)-1], true
	}
	if !out.valid() {
		return Devices{}, ErrReport
	}
	return out, nil
}

func inspectDisk(src deviceSources, name, dir string, size uint64, mounts map[string][]blockMount, swaps map[string]bool) BlockDisk {
	d := BlockDisk{Name: name, Size: size}
	d.Model = firstText(filepath.Join(dir, "device", "model"))
	d.Serial = firstText(filepath.Join(dir, "device", "serial"), filepath.Join(dir, "serial"))
	d.WWN = firstText(filepath.Join(dir, "wwid"), filepath.Join(dir, "device", "wwid"))
	d.Rotational = sysText(filepath.Join(dir, "queue", "rotational")) == "1"
	d.ReadOnly = sysText(filepath.Join(dir, "ro")) == "1"
	d.Removable = sysText(filepath.Join(dir, "removable")) == "1"
	sector := int(sysNumber(filepath.Join(dir, "queue", "logical_block_size")))
	if sector < 512 || sector > 4096 {
		sector = 512
	}
	head := readHead(filepath.Join(src.Dev, name))
	d.Table, d.TableID = ProbeTable(head, sector)
	children, _ := os.ReadDir(dir)
	for _, child := range children {
		partDir := filepath.Join(dir, child.Name())
		number := sysNumber(filepath.Join(partDir, "partition"))
		if !child.IsDir() || number == 0 || number > 1<<20 || !deviceName(child.Name()) {
			continue
		}
		if len(d.Parts) == maxBlockParts {
			break
		}
		p := BlockPart{Name: child.Name(), Number: uint32(number), Size: sysNumber(filepath.Join(partDir, "size")) * 512}
		fillPart(src, &p, partDir, readHead(filepath.Join(src.Dev, p.Name)), mounts, swaps)
		d.Parts = append(d.Parts, p)
	}
	slices.SortFunc(d.Parts, func(a, b BlockPart) int { return int(a.Number) - int(b.Number) })
	if len(d.Parts) == 0 && d.Table == "" {
		p := BlockPart{Name: name, Size: size}
		fillPart(src, &p, dir, head, mounts, swaps)
		if p.Filesystem != "" || p.Busy() {
			d.Parts = []BlockPart{p}
		}
	}
	d.Class = classOf(d)
	return d
}

func readHead(path string) []byte {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, e := f.Stat(); e != nil || st.Mode()&os.ModeDevice == 0 && !st.Mode().IsRegular() {
		return nil // regular files only for tests on a fake /dev
	}
	buf := make([]byte, deviceProbeBytes)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil
	}
	return buf[:n]
}

func placeMounts(list []blockMount, space func(string) *BlockSpace) ([]string, string, *BlockSpace) {
	points := []string{}
	kind := ""
	for _, m := range list {
		if len(m.point) <= maxDeviceMount && !strings.ContainsAny(m.point, "\x00\r\n") {
			points = append(points, m.point)
			if kind == "" {
				kind = m.kind
			}
		}
	}
	slices.Sort(points)
	points = slices.Compact(points)
	// The shortest points are the ones an operator chose; deep bind
	// mounts of the same filesystem come after them.
	slices.SortStableFunc(points, func(a, b string) int { return len(a) - len(b) })
	if len(points) > maxBlockMounts {
		points = points[:maxBlockMounts]
	}
	var sp *BlockSpace
	if len(points) > 0 && space != nil {
		sp = space(points[0])
	}
	slices.Sort(points)
	if len(points) == 0 {
		points = nil
	}
	return points, kind, sp
}

func fillPart(src deviceSources, p *BlockPart, dir string, head []byte, mounts map[string][]blockMount, swaps map[string]bool) {
	if sig, ok := ProbeSignature(head); ok {
		p.Filesystem, p.UUID, p.Label = sig.Filesystem, sig.UUID, sig.Label
	}
	var kind string
	p.Mounts, kind, p.Space = placeMounts(deviceMounts(mounts, dir, p.Name), src.Space)
	if p.Filesystem == "" {
		p.Filesystem = kind
	}
	p.Swap = swaps[p.Name]
	seen := map[string]bool{}
	var walk func(string, int)
	walk = func(dir string, depth int) {
		names, _ := os.ReadDir(filepath.Join(dir, "holders"))
		for _, n := range names {
			name := n.Name()
			if depth > 4 || seen[name] || !deviceName(name) || len(p.Holders) == maxBlockHolders {
				continue
			}
			seen[name] = true
			hdir := filepath.Join(src.Sys, "block", name)
			h := BlockHolder{Name: name, Kind: "dm", Mapper: sysText(filepath.Join(hdir, "dm", "name"))}
			uuid := sysText(filepath.Join(hdir, "dm", "uuid"))
			switch {
			case exists(filepath.Join(hdir, "md")):
				h.Kind = "raid"
			case strings.HasPrefix(uuid, "LVM-"):
				h.Kind = "lvm"
			case strings.HasPrefix(uuid, "CRYPT-"):
				h.Kind = "crypt"
			}
			h.Mounts, h.Filesystem, h.Space = placeMounts(deviceMounts(mounts, hdir, name), src.Space)
			h.Swap = swaps[name]
			p.Holders = append(p.Holders, h)
			walk(hdir, depth+1)
		}
	}
	walk(dir, 0)
	slices.SortFunc(p.Holders, func(a, b BlockHolder) int { return strings.Compare(a.Name, b.Name) })
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func deviceMounts(mounts map[string][]blockMount, dir, name string) []blockMount {
	return append(slices.Clone(mounts[sysText(filepath.Join(dir, "dev"))]), mounts["name:"+name]...)
}
