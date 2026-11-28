// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func ext4Image(uuid byte, label string) []byte {
	b := make([]byte, deviceProbeBytes)
	sb := b[1024:]
	binary.LittleEndian.PutUint16(sb[0x38:], 0xEF53)
	binary.LittleEndian.PutUint32(sb[0x5C:], 0x4)
	binary.LittleEndian.PutUint32(sb[0x60:], 0x40)
	copy(sb[0x68:0x78], bytes.Repeat([]byte{uuid}, 16))
	copy(sb[0x78:0x88], label)
	return b
}

func gptImage() []byte {
	b := make([]byte, deviceProbeBytes)
	b[510], b[511] = 0x55, 0xAA
	b[446+4] = 0xEE // protective MBR entry
	copy(b[512:], "EFI PART")
	copy(b[512+56:512+72], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	return b
}

func TestProbeSignatureAndTableReadOnlyBytes(t *testing.T) {
	sig, ok := ProbeSignature(ext4Image(0xab, "data"))
	if !ok || sig.Filesystem != "ext4" || sig.UUID != "abababab-abab-abab-abab-abababababab" || sig.Label != "data" {
		t.Fatalf("ext4 %+v", sig)
	}
	xfs := make([]byte, 4096)
	copy(xfs, "XFSB")
	xfs[32] = 1
	copy(xfs[108:], "logs")
	if sig, ok := ProbeSignature(xfs); !ok || sig.Filesystem != "xfs" || sig.Label != "logs" || !strings.HasPrefix(sig.UUID, "01000000-") {
		t.Fatalf("xfs %+v", sig)
	}
	swap := make([]byte, 4096)
	copy(swap[4096-10:], "SWAPSPACE2")
	if sig, ok := ProbeSignature(swap); !ok || sig.Filesystem != "swap" || sig.UUID != "" {
		t.Fatalf("swap %+v", sig)
	}
	lvm := make([]byte, 1024)
	copy(lvm[512:], "LABELONE")
	copy(lvm[512+24:], "LVM2 001")
	if sig, ok := ProbeSignature(lvm); !ok || sig.Filesystem != "LVM2_member" {
		t.Fatal("lvm")
	}
	if _, ok := ProbeSignature(make([]byte, deviceProbeBytes)); ok {
		t.Fatal("empty device has a signature")
	}
	if kind, id := ProbeTable(gptImage(), 512); kind != "gpt" || id != "04030201-0605-0807-090a-0b0c0d0e0f10" {
		t.Fatal("gpt", kind, id)
	}
	dos := make([]byte, 1024)
	dos[510], dos[511] = 0x55, 0xAA
	dos[446+4] = 0x83
	binary.LittleEndian.PutUint32(dos[440:], 0xdeadbeef)
	if kind, id := ProbeTable(dos, 512); kind != "dos" || id != "deadbeef" {
		t.Fatal("dos", kind, id)
	}
	fat := make([]byte, 1024)
	fat[510], fat[511] = 0x55, 0xAA
	copy(fat[82:], "FAT32   ")
	if kind, _ := ProbeTable(fat, 512); kind != "" {
		t.Fatal("FAT boot sector read as a partition table")
	}
	if kind, _ := ProbeTable(make([]byte, 1024), 512); kind != "" {
		t.Fatal("blank disk has a table")
	}
}

type fakeHost struct {
	t    *testing.T
	root string
}

func (h fakeHost) write(path, body string) {
	h.t.Helper()
	full := filepath.Join(h.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h fakeHost) image(name string, b []byte) {
	h.t.Helper()
	h.write(filepath.Join("dev", name), string(b))
}

func TestInspectDevicesClassifiesSystemAdditionalUnused(t *testing.T) {
	h := fakeHost{t, t.TempDir()}
	// sda: system disk, GPT, sda1 /boot/efi, sda2 LVM PV -> dm-0 mounted at /
	h.write("sys/block/sda/size", "2000\n")
	h.write("sys/block/sda/device/model", "Fast SSD  \n")
	h.write("sys/block/sda/device/serial", "S1\n")
	h.write("sys/block/sda/queue/rotational", "0\n")
	h.write("sys/block/sda/sda1/partition", "1\n")
	h.write("sys/block/sda/sda1/size", "100\n")
	h.write("sys/block/sda/sda1/dev", "8:1\n")
	h.write("sys/block/sda/sda2/partition", "2\n")
	h.write("sys/block/sda/sda2/size", "1800\n")
	h.write("sys/block/sda/sda2/dev", "8:2\n")
	h.write("sys/block/sda/sda2/holders/dm-0", "")
	h.write("sys/block/dm-0/size", "1800\n")
	h.write("sys/block/dm-0/dev", "253:0\n")
	h.write("sys/block/dm-0/dm/name", "vg-root\n")
	h.write("sys/block/dm-0/dm/uuid", "LVM-abc\n")
	h.image("sda", gptImage())
	// sdb: additional, whole-disk ext4 mounted at /data (and a bind mount)
	h.write("sys/block/sdb/size", "4000\n")
	h.write("sys/block/sdb/dev", "8:16\n")
	h.write("sys/block/sdb/wwid", "naa.5000\n")
	h.image("sdb", ext4Image(0x11, "data"))
	// sdc: unused, ext4 present but not mounted; sdd: blank; loop0 skipped
	h.write("sys/block/sdc/size", "4000\n")
	h.write("sys/block/sdc/dev", "8:32\n")
	h.image("sdc", ext4Image(0x22, ""))
	h.write("sys/block/sdd/size", "4000\n")
	h.write("sys/block/sdd/dev", "8:48\n")
	h.image("sdd", make([]byte, 4096))
	h.write("sys/block/loop0/size", "10\n")
	h.write("proc/mountinfo", strings.Join([]string{
		"25 1 253:0 / / rw - ext4 /dev/mapper/vg-root rw",
		"26 25 8:1 / /boot/efi rw - vfat /dev/sda1 rw",
		"27 25 8:16 / /data rw - ext4 /dev/sdb rw",
		"28 25 8:16 /x /data/very/deep/bind rw - ext4 /dev/sdb rw",
		"29 25 8:16 / /var/lib/docker/overlay2/x rw - ext4 /dev/sdb rw",
		"30 25 0:22 / /run rw - tmpfs tmpfs rw",
	}, "\n")+"\n")
	h.write("proc/swaps", "Filename Type Size Used Priority\n")
	src := deviceSources{Sys: filepath.Join(h.root, "sys"), Dev: filepath.Join(h.root, "dev"), MountInfo: filepath.Join(h.root, "proc/mountinfo"), Swaps: filepath.Join(h.root, "proc/swaps"), Space: func(string) *BlockSpace { return &BlockSpace{Total: 100, Used: 40, Available: 50} }}
	d, err := inspectDevices(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Disks) != 4 {
		t.Fatalf("disks %+v", d.Disks)
	}
	sda, sdb, sdc, sdd := d.Disks[0], d.Disks[1], d.Disks[2], d.Disks[3]
	if sda.Class != "system" || sda.Table != "gpt" || sda.Model != "Fast SSD" || sda.Serial != "S1" || len(sda.Parts) != 2 || sda.Parts[1].Holders[0].Kind != "lvm" || sda.Parts[1].Holders[0].Mounts[0] != "/" || sda.Parts[0].Mounts[0] != "/boot/efi" || !sda.Parts[1].Busy() {
		t.Fatalf("sda %+v", sda)
	}
	if sdb.Class != "additional" || len(sdb.Parts) != 1 || sdb.Parts[0].Number != 0 || sdb.Parts[0].Filesystem != "ext4" || sdb.Parts[0].UUID != "11111111-1111-1111-1111-111111111111" || strings.Join(sdb.Parts[0].Mounts, ",") != "/data,/data/very/deep/bind" || sdb.Parts[0].Space == nil || sdb.WWN != "naa.5000" {
		t.Fatalf("sdb %+v", sdb)
	}
	if sdc.Class != "unused" || len(sdc.Parts) != 1 || sdc.Parts[0].Busy() || sdc.Parts[0].Filesystem != "ext4" {
		t.Fatalf("sdc %+v", sdc)
	}
	if sdd.Class != "unused" || len(sdd.Parts) != 0 {
		t.Fatalf("sdd %+v", sdd)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	r := Report{Kind: "node-observation", Schema: 1, Cluster: [32]byte{1}, Node: "node-a", Key: [32]byte(key.Public().(ed25519.PublicKey)), Index: 2, At: 1000, Devices: &d}
	r.Signature = ed25519.Sign(key, SigningBytes(r))
	raw, _ := json.Marshal(r)
	if got, err := Decode(raw); err != nil || got.Source() != "devices" {
		t.Fatal("devices report", err)
	}
	// A report that calls a disk holding "/" anything but system is refused.
	lie := d
	lie.Disks = append([]BlockDisk(nil), d.Disks...)
	lie.Disks[0].Class = "unused"
	if lie.valid() {
		t.Fatal("system disk reported as unused")
	}
}

func TestDevicesStayWithinBudget(t *testing.T) {
	disks := []BlockDisk{}
	for i := 0; i < maxBlockDisks; i++ {
		d := BlockDisk{Name: "sd" + string(rune('a'+i/26)) + string(rune('a'+i%26)), Class: "additional", Size: 1}
		for j := 1; j <= 4; j++ {
			d.Parts = append(d.Parts, BlockPart{Name: d.Name + string(rune('0'+j)), Number: uint32(j), Size: 1, Mounts: []string{"/" + strings.Repeat("m", 300)}})
		}
		disks = append(disks, d)
	}
	if (Devices{Disks: disks}).valid() {
		t.Fatal("oversized inventory accepted")
	}
}

func TestInspectDevicesListsLVMBundles(t *testing.T) {
	h := fakeHost{t, t.TempDir()}
	h.write("sys/block/sda/size", "2000\n")
	h.write("sys/block/sda/dev", "8:0\n")
	h.image("sda", ext4Image(0x33, ""))
	// sdb and sdc are the PVs of mirror bundle "my-pool": rimage sub-volumes
	// over each, and the data volume (dm-2) mounted at /var/lib/sfc-disks/p.
	for i, disk := range []string{"sdb", "sdc"} {
		h.write("sys/block/"+disk+"/size", "4000\n")
		h.write("sys/block/"+disk+"/dev", "8:"+strconv.Itoa(16*(i+1))+"\n")
		h.write("sys/block/"+disk+"/serial", "S-"+disk+"\n")
		h.image(disk, make([]byte, 4096))
		sub := "dm-" + strconv.Itoa(i)
		h.write("sys/block/"+disk+"/holders/"+sub, "")
		h.write("sys/block/"+sub+"/size", "3900\n")
		h.write("sys/block/"+sub+"/dev", "253:"+strconv.Itoa(i)+"\n")
		h.write("sys/block/"+sub+"/dm/name", "sfc--my--pool-data_rimage_"+strconv.Itoa(i)+"\n")
		h.write("sys/block/"+sub+"/dm/uuid", "LVM-x"+strconv.Itoa(i)+"\n")
		h.write("sys/block/"+sub+"/holders/dm-2", "")
	}
	h.write("sys/block/dm-2/size", "3900\n")
	h.write("sys/block/dm-2/dev", "253:2\n")
	h.write("sys/block/dm-2/dm/name", "sfc--my--pool-data\n")
	h.write("sys/block/dm-2/dm/uuid", "LVM-y\n")
	h.image("dm-2", ext4Image(0x44, ""))
	h.write("proc/mountinfo", strings.Join([]string{
		"25 1 8:0 / / rw - ext4 /dev/sda rw",
		"26 25 253:2 / /var/lib/sfc-disks/p rw - ext4 /dev/mapper/sfc--my--pool-data rw",
	}, "\n")+"\n")
	h.write("proc/swaps", "Filename Type Size Used Priority\n")
	src := deviceSources{Sys: filepath.Join(h.root, "sys"), Dev: filepath.Join(h.root, "dev"), MountInfo: filepath.Join(h.root, "proc/mountinfo"), Swaps: filepath.Join(h.root, "proc/swaps")}
	d, err := inspectDevices(src)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, disk := range d.Disks {
		names = append(names, disk.Name+":"+disk.Class+":"+disk.Bundle+":"+disk.Kind)
	}
	if strings.Join(names, ",") != "dm-2:additional:my-pool:bundle,sda:system::,sdb:bundle-member:my-pool:,sdc:bundle-member:my-pool:" {
		t.Fatal(names)
	}
	if p := d.Disks[0].Parts; len(p) != 1 || p[0].Filesystem != "ext4" || p[0].Mounts[0] != "/var/lib/sfc-disks/p" {
		t.Fatalf("bundle device %+v", d.Disks[0])
	}
	for name, want := range map[string][2]string{"sfc--my--pool-data": {"my-pool", ""}, "sfc--a-data_rmeta_1": {"a", "rmeta_1"}, "vg-root": {}, "sfc--a-other": {}, "sfc--A-data": {}} {
		if b, sub := LVMBundle(name); b != want[0] || sub != want[1] {
			t.Error(name, b, sub)
		}
	}
}
