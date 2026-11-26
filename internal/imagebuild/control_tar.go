// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"time"
)

// SecretValue is ephemeral, already-authorized Vault material. Native input
// code cannot serialize it into a journal, public reply or incidental log.
type SecretValue struct {
	Reference SecretMount
	Value     []byte
}

func (SecretValue) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (SecretValue) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[redacted build secret]") }

// writeControlTAR consumes the same frozen source policy as job admission.
// Secret files are separate from public Dockerfile ARGs and never included in
// context/, result archives, shared state or the native journal.
func writeControlTAR(ctx context.Context, w io.Writer, spec JobSpec, inputs []FrozenSource, values []SecretValue) error {
	return writeControlFilesTAR(ctx, w, spec, inputs, values, nil)
}

func writeControlFilesTAR(ctx context.Context, w io.Writer, spec JobSpec, inputs []FrozenSource, values []SecretValue, files []buildTrustFile) error {
	if ctx == nil || w == nil || spec.Validate() != nil || ValidateJobInputs(spec, inputs) != nil || len(values) != len(spec.Context.Secrets) {
		return ErrInvalid
	}
	byID := map[string]SecretValue{}
	bytes := 0
	for _, value := range values {
		if len(value.Value) > 128<<10 {
			return ErrInvalid
		}
		if _, exists := byID[value.Reference.ID]; exists {
			return ErrInvalid
		}
		byID[value.Reference.ID] = value
		bytes += len(value.Value)
	}
	if bytes > 4<<20 {
		return ErrInvalid
	}
	publicBytes := 0
	for _, file := range files {
		if len(file.data) > MaxBuildTrustBytes+(64<<10)-publicBytes {
			return ErrInvalid
		}
		publicBytes += len(file.data)
	}
	for _, ref := range spec.Context.Secrets {
		if byID[ref.ID].Reference != ref {
			return ErrInvalid
		}
	}
	policy, err := SourcePolicy(inputs)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(&contextTARWriter{ctx: ctx, output: w, remaining: int64(bytes + publicBytes + len(policy) + (len(values)+len(files)+5)*(6<<10) + 1024)})
	file := func(name string, mode int64, uid int, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Uid: uid, Gid: uid, Typeflag: tar.TypeReg, Size: int64(len(data)), ModTime: time.Unix(0, 0), Format: tar.FormatPAX}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := file("source-policy.json", 0444, 0, policy); err != nil {
		return err
	}
	if len(files) > 1 {
		if err := tw.WriteHeader(&tar.Header{Name: "tls/", Mode: 0555, Uid: 0, Gid: 0, Typeflag: tar.TypeDir, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}); err != nil {
			return err
		}
	}
	for _, entry := range files {
		if err := file(entry.name, 0444, 0, entry.data); err != nil {
			return err
		}
	}
	if len(values) > 0 {
		if err := tw.WriteHeader(&tar.Header{Name: "secrets/", Mode: 0500, Uid: 1000, Gid: 1000, Typeflag: tar.TypeDir, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}); err != nil {
			return err
		}
		for _, ref := range spec.Context.Secrets {
			if err := file("secrets/"+ref.ID, 0400, 1000, byID[ref.ID].Value); err != nil {
				return err
			}
		}
	}
	return tw.Close()
}
