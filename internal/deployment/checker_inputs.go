// SPDX-License-Identifier: Apache-2.0

package deployment

// The accepted Task config and original input recipe must carry the same
// lifecycle selection. It is not a mutable name/latest lookup during Start.
func (s ComposeService) CheckLifecycleNeeds(n Needs) error {
	if (s.LifecycleSources == nil) != (n.Lifecycle == nil) {
		return ErrInputs
	}
	if n.Lifecycle != nil && (n.Lifecycle.Validate() != nil || !n.Lifecycle.Equal(*s.LifecycleSources)) {
		return ErrInputs
	}
	if s.LifecycleProgram != nil {
		program := s.LifecycleProgram
		if program.Validate(program.Cluster) != nil || program.Tenant != n.Use.Tenant || program.Service != n.Use.Service {
			return ErrInputs
		}
		selection, err := program.Selection()
		if err != nil || !sameCheckerSelection(selection, n.Lifecycle) {
			return ErrInputs
		}
	} else if s.LifecycleSources != nil {
		return ErrInputs
	}
	return nil
}
