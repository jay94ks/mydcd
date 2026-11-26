// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"debug/elf"
	"io"
	"math"
)

// Both compiler publication and cache adoption/read use this same parser.
// An ELF match is content validation, not a process/Task permission receipt.
func verifyCompileELF(file io.ReaderAt, target string) error {
	binary, err := elf.NewFile(file)
	if err != nil {
		return ErrSource
	}
	if target != "amd64" && target != "arm64" || binary.Class != elf.ELFCLASS64 || binary.Data != elf.ELFDATA2LSB || binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN || target == "amd64" && binary.Machine != elf.EM_X86_64 || target == "arm64" && binary.Machine != elf.EM_AARCH64 {
		return ErrSource
	}
	executable := false
	for _, p := range binary.Progs {
		if p.Type == elf.PT_INTERP {
			return ErrSource
		}
		if p.Type != elf.PT_LOAD {
			continue
		}
		if p.Filesz > p.Memsz || p.Off > math.MaxInt64 || p.Filesz > math.MaxInt64-p.Off {
			return ErrSource
		}
		if p.Filesz > 0 {
			var last [1]byte
			if n, err := file.ReadAt(last[:], int64(p.Off+p.Filesz-1)); err != nil || n != 1 {
				return ErrSource
			}
		}
		if p.Flags&elf.PF_X != 0 && binary.Entry >= p.Vaddr && binary.Entry-p.Vaddr < p.Filesz {
			executable = true
		}
	}
	if !executable {
		return ErrSource
	}
	return nil
}
