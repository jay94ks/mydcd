// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
)

// Source is an external image dependency, including COPY/RUN --from images.
// Local stages/scratch are not registry lookups. A native build must resolve
// and freeze every Source before passing the plan to BuildKit.
type Source struct {
	Reference string
	Platform  string
	Stage     int
	Kind      string
	Line      int
}

func (s Source) Valid() bool {
	named, err := reference.ParseNormalizedNamed(s.Reference)
	return err == nil && reference.TagNameOnly(named).String() == s.Reference && len(s.Reference) <= 512 && ValidPlatform(s.Platform) && s.Stage >= 0 && s.Stage < MaxTreeEntries && s.Line >= 0 && (s.Kind == "from" || s.Kind == "copy" || s.Kind == "mount" || s.Kind == BuilderKind && s.Stage == 0 && s.Line == 0)
}

type DockerfilePlan struct {
	Sources []Source
	Stages  []string
}
type DockerfileOptions struct {
	Platform, BuildPlatform string
	Arguments               map[string]string // public arguments only; Vault values are mounts
}

func AnalyzeDockerfile(body []byte, options DockerfileOptions) (DockerfilePlan, error) {
	if len(body) == 0 || len(body) > MaxDockerfileBytes || !ValidPlatform(options.Platform) || !ValidPlatform(options.BuildPlatform) || len(options.Arguments) > 128 {
		return DockerfilePlan{}, ErrInvalid
	}
	// BuildKit's bundled frontend is fixed by the builder digest. A Dockerfile
	// cannot silently cause another unapproved frontend image to be pulled.
	if _, _, _, syntax := parser.DetectSyntax(body); syntax {
		return DockerfilePlan{}, ErrInvalid
	}
	ast, err := parser.Parse(bytes.NewReader(body))
	if err != nil {
		return DockerfilePlan{}, ErrInvalid
	}
	stages, globals, err := instructions.Parse(ast.AST, nil)
	if err != nil || len(stages) == 0 || len(stages) > 256 {
		return DockerfilePlan{}, ErrInvalid
	}
	lex := shell.NewLex(ast.EscapeToken)
	env := platformArguments(options.Platform, "TARGET")
	env = append(env, platformArguments(options.BuildPlatform, "BUILD")...)
	env = append(env, "TARGETSTAGE=default")
	for index, automatic := range env {
		key, _, _ := strings.Cut(automatic, "=")
		if value, ok := options.Arguments[key]; ok {
			env[index] = key + "=" + value
		}
	}
	expand := func(value string) (string, error) {
		word, _, err := lex.ProcessWord(value, shell.EnvsFromSlice(env))
		return word, err
	}
	for key, value := range options.Arguments {
		if key == "" || key == "BUILDKIT_SYNTAX" || strings.Contains(key, "=") || len(key) > 128 || len(value) > 16<<10 || strings.ContainsAny(key+value, "\x00\r\n") {
			return DockerfilePlan{}, ErrInvalid
		}
	}
	for _, command := range globals {
		for _, arg := range command.Args {
			value, override := options.Arguments[arg.Key]
			if !override {
				if arg.Value == nil {
					continue
				}
				value, err = expand(*arg.Value)
				if err != nil {
					return DockerfilePlan{}, ErrInvalid
				}
			}
			env = append(env, arg.Key+"="+value)
		}
	}
	aliases := map[string]int{}
	plan := DockerfilePlan{}
	for index, stage := range stages {
		if len(stage.Commands) > MaxTreeEntries {
			return DockerfilePlan{}, ErrInvalid
		}
		if stage.Name != "" {
			key := strings.ToLower(stage.Name)
			if _, duplicate := aliases[key]; duplicate {
				return DockerfilePlan{}, ErrInvalid
			}
			aliases[key] = index
		}
		plan.Stages = append(plan.Stages, stage.Name)
	}
	edges := make([][]int, len(stages))
	add := func(value, platform, kind string, index, line int, numeric bool) error {
		if value == "scratch" && kind == "from" {
			return nil
		}
		dependency, local := aliases[strings.ToLower(value)]
		// FROM inherits only an earlier named stage. COPY/RUN may refer to
		// later stages. In particular FROM alpine AS alpine is an image pull,
		// not a self-cycle; this matches BuildKit's dispatch-state insertion.
		if kind == "from" && local && dependency >= index {
			local = false
		}
		if !local && numeric {
			if number, err := strconv.Atoi(value); err == nil && number >= 0 {
				if number >= len(stages) {
					return ErrInvalid
				}
				dependency, local = number, true
			}
		}
		if local {
			edges[index] = append(edges[index], dependency)
			return nil
		}
		named, err := reference.ParseNormalizedNamed(value)
		if err != nil || len(value) > 512 || strings.Contains(value, "$") {
			return ErrInvalid
		}
		ref := reference.TagNameOnly(named).String()
		plan.Sources = append(plan.Sources, Source{Reference: ref, Platform: platform, Stage: index, Kind: kind, Line: line})
		return nil
	}
	for index, stage := range stages {
		base, err := expand(stage.BaseName)
		if err != nil || base == "" {
			return DockerfilePlan{}, ErrInvalid
		}
		platform := options.Platform
		if stage.Platform != "" {
			platform, err = expand(stage.Platform)
			if err != nil || !ValidPlatform(platform) {
				return DockerfilePlan{}, ErrInvalid
			}
		}
		line := 0
		if len(stage.Location) > 0 {
			line = stage.Location[0].Start.Line
		}
		if err := add(base, platform, "from", index, line, false); err != nil {
			return DockerfilePlan{}, err
		}
		for _, command := range stage.Commands {
			switch command := command.(type) {
			case *instructions.CopyCommand:
				if command.From != "" {
					if err := add(command.From, platform, "copy", index, firstLine(command.Location()), true); err != nil {
						return DockerfilePlan{}, err
					}
				}
			case *instructions.RunCommand:
				for _, mount := range instructions.GetMounts(command) {
					if mount.From != "" {
						if err := add(mount.From, platform, "mount", index, firstLine(command.Location()), true); err != nil {
							return DockerfilePlan{}, err
						}
					}
				}
			}
		}
	}
	// A stage cannot consume itself or a dependency cycle. Resolve all names
	// before checking so a forward COPY reference cannot bypass this boundary.
	colors := make([]uint8, len(stages))
	var visit func(int) bool
	visit = func(n int) bool {
		if colors[n] == 1 {
			return false
		}
		if colors[n] == 2 {
			return true
		}
		colors[n] = 1
		for _, next := range edges[n] {
			if !visit(next) {
				return false
			}
		}
		colors[n] = 2
		return true
	}
	for index := range stages {
		if !visit(index) {
			return DockerfilePlan{}, ErrInvalid
		}
	}
	return plan, nil
}
func firstLine(location []parser.Range) int {
	if len(location) == 0 {
		return 0
	}
	return location[0].Start.Line
}
func platformArguments(platform, prefix string) []string {
	parts := strings.Split(platform, "/")
	variant := ""
	if len(parts) == 3 {
		variant = parts[2]
	}
	return []string{prefix + "PLATFORM=" + platform, prefix + "OS=" + parts[0], prefix + "OSVERSION=", prefix + "ARCH=" + parts[1], prefix + "VARIANT=" + variant}
}

type FrozenSource struct {
	Source Source
	Image  string // canonical image@sha256, same repository as the requested source
}

// FreezeSources is also the adapter's only dependency enumeration. Resolve
// performs current tenant trust/credential selection before registry I/O.
// Calling it with a denial never leaves a partial success plan to execute.
func FreezeSources(plan DockerfilePlan, resolve func(Source) (string, error)) ([]FrozenSource, error) {
	if resolve == nil || len(plan.Stages) == 0 || len(plan.Sources) > MaxTreeEntries {
		return nil, ErrInvalid
	}
	var frozen []FrozenSource
	resolved := map[string]string{}
	for _, source := range plan.Sources {
		original, err := reference.ParseNormalizedNamed(source.Reference)
		if err != nil || !source.Valid() || source.Stage >= len(plan.Stages) {
			return nil, ErrInvalid
		}
		key := source.Reference + "\x00" + source.Platform
		image, found := resolved[key]
		if !found {
			image, err = resolve(source)
		}
		if err != nil {
			code := ErrSourceFetch
			if errors.Is(err, ErrUntrustedBase) {
				code = ErrUntrustedBase
			}
			return nil, fmt.Errorf("%w: stage %d", code, source.Stage)
		}
		canonical, err := parseCanonical(image)
		if err != nil || canonical.Digest().Algorithm().String() != "sha256" || canonical.Name() != original.Name() || len(image) > 512 {
			return nil, ErrInvalid
		}
		resolved[key] = canonical.String()
		frozen = append(frozen, FrozenSource{source, canonical.String()})
	}
	return slices.Clip(frozen), nil
}
