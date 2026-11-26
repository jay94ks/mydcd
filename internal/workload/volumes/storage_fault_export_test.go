// SPDX-License-Identifier: Apache-2.0

package volumes

// External native boundary tests close the real private bbolt store at the
// permit-to-sync boundary. This helper is absent from product builds and does
// not replace storage, the provider, the gate algorithm or the native driver.
func CloseActivationStorageForTest(s *Activations) error { return s.db.Close() }
