// SPDX-License-Identifier: Apache-2.0

package imagebuild

import "github.com/jay94ks/seafield/internal/registryclient"

// SelectPullSource is shared by the native session and its tests. Registry
// hosts are not credential keys: choose only a repository present in the
// accepted frozen inputs. Repeated stages/digests of that repository use the
// same registry source selection, and the owner rechecks its original binding.
func SelectPullSource(inputs []FrozenSource, challenge registryclient.PullTokenChallenge) (Source, error) {
	sources, err := SelectPullSources(inputs, challenge)
	if err != nil || len(sources) != 1 {
		return Source{}, ErrSourceFetch
	}
	return sources[0], nil
}

// One selected frozen source per requested repository; duplicate scopes do
// not duplicate readers. The runtime must separately prove a common owner.
func SelectPullSources(inputs []FrozenSource, challenge registryclient.PullTokenChallenge) ([]Source, error) {
	if len(challenge.Scopes) == 0 || len(challenge.Scopes) > 8 {
		return nil, ErrSourceFetch
	}
	seen := map[string]bool{}
	var sources []Source
	for _, scope := range challenge.Scopes {
		if seen[scope] {
			continue
		}
		one := challenge
		one.Scopes = []string{scope}
		found := false
		for _, input := range inputs {
			if input.Source.Valid() && one.Valid(input.Image) {
				sources = append(sources, input.Source)
				seen[scope], found = true, true
				break
			}
		}
		if !found {
			return nil, ErrSourceFetch
		}
	}
	return sources, nil
}
