// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/containerops"
)

func TestSecretDeliveryTargetsAndNativeEnvironmentNeverChangePublicProcess(t *testing.T) {
	for _, target := range []string{"/etc/app/key.pem", "/run/secrets/key", "/opt/app/config/signing.key"} {
		if !SecretFileTarget(target) {
			t.Fatal("valid target denied", target)
		}
	}
	for _, target := range []string{"/", "/proc/key", "/sys/key", "/dev/key", "/etc", "/etc/resolv.conf", "/etc/hosts/child", "/etc/hostname", "/a/../b", "/run/secrets/", "relative", "/a\x00b"} {
		if SecretFileTarget(target) {
			t.Fatal("reserved or unclean target admitted", target)
		}
	}
	for _, name := range []string{"", "4KEY", "A=B", "A/B", "A-B", "A\x00B", strings.Repeat("A", 257)} {
		if SecretEnvironmentName(name) {
			t.Fatal("invalid env name admitted", name)
		}
	}
	if err := CheckSecretImageMounts(map[string]struct{}{"/etc/app": {}}, []string{"/etc/app/key.pem"}); err == nil {
		t.Fatal("image Volume hides secret")
	}
	root := t.TempDir()
	file := filepath.Join(root, "value")
	if err := os.WriteFile(file, []byte("private-env-marker-610"), 0600); err != nil {
		t.Fatal(err)
	}
	projection := InputFile{Source: file, Target: "APP_PASSWORD", Mode: 0400, Kind: "env"}
	base := []string{"PATH=/bin", "APP_PASSWORD=image-default", "PLAIN=literal"}
	got, err := inputEnvironment(context.Background(), base, []InputFile{projection})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"PATH=/bin", "APP_PASSWORD=private-env-marker-610", "PLAIN=literal"}) || base[1] != "APP_PASSWORD=image-default" {
		t.Fatal("env merge mutated public recipe or duplicated image default")
	}
	if len(inputMounts([]InputFile{projection})) != 0 || len(mountedInputFiles([]InputFile{projection})) != 0 {
		t.Fatal("environment projection became a container mount")
	}
	for _, value := range [][]byte{{0, 1}, {0xff}, []byte(strings.Repeat("x", (64<<10)+1))} {
		if err = os.WriteFile(file, value, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = inputEnvironment(context.Background(), base, []InputFile{projection}); !errors.Is(err, ErrInputMount) {
			t.Fatal("invalid native env value admitted", err)
		}
	}
	if err = os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(root, "foreign"), file); err != nil {
		t.Fatal(err)
	}
	if _, err = readInputValue(context.Background(), projection, 64<<10); !errors.Is(err, ErrInputMount) {
		t.Fatal("symlink input admitted", err)
	}
}

func TestSecretLogRedactionPrecedesFiniteOutputBudgetAndDockerFraming(t *testing.T) {
	value := []byte("private-value-marker-714")
	values := []containerops.RedactionValue{{Reference: "tenant/signing/KEY", Value: value}}
	input := append(observationFrame(1, "visible private-val"), observationFrame(2, "diagnostic private-value-marker-714")...)
	input = append(input, observationFrame(1, "ue-marker-714 tail")...)
	closed := false
	stdout, stderr, truncated, err := readRedactedObservationLogs(observationTestBody{strings.NewReader(string(input)), &closed}, false, containerops.MaxOutput, values)
	if err != nil || !closed || truncated {
		t.Fatal("filtered Docker frames", err)
	}
	if strings.Contains(string(stdout)+string(stderr), string(value)) || !strings.Contains(string(stdout), "«가림: tenant/signing/KEY»") || !strings.Contains(string(stderr), "«가림: tenant/signing/KEY»") {
		t.Fatal("secret escaped separate framed streams")
	}
	closed = false
	stdout, stderr, truncated, err = readRedactedObservationLogs(observationTestBody{strings.NewReader(string(value) + strings.Repeat("x", 64)), &closed}, true, 5, values)
	if err != nil || !closed || !truncated || len(stdout)+len(stderr) != 5 || strings.Contains(string(stdout), "priva") {
		t.Fatal("budget applied before redaction", err)
	}
}
