// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"io"
)

func ReadFrame(r io.Reader, limit int) (Frame, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}
	f, n, err := validateHeader(header[:], limit)
	if err != nil {
		return Frame{}, err
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, err
	}
	return parseFields(f, body)
}
func WriteFrame(w io.Writer, f Frame) error {
	b, err := Encode(f)
	if err != nil {
		return err
	}
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
