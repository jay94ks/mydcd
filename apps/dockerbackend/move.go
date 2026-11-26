// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"io"
	"net/http"
	"os"
)

// This is sample application behavior, not an engine lifecycle/Volume path.
// A single explicit write gets a fixed durable result. A lost reply must be
// read back; PUT never overwrites an earlier result under the same filename.
func registerMoveFixture() {
	if os.Getenv("MYDC_MOVE_FIXTURE") != "1" {
		return
	}
	http.HandleFunc("/move-state", func(w http.ResponseWriter, r *http.Request) {
		const limit = 32 << 10
		if r.Method != http.MethodGet && r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var data []byte
		var err error
		if r.Method == http.MethodPut {
			defer r.Body.Close()
			data, err = io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
			if err != nil || len(data) == 0 {
				http.Error(w, "invalid bounded write", http.StatusBadRequest)
				return
			}
		}
		root, err := os.OpenRoot("/data")
		if err != nil {
			http.Error(w, "Volume unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodPut {
			file, openErr := root.OpenFile("move-target-write", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			err = openErr
			if err == nil {
				_, err = file.Write(data)
				if err == nil {
					err = file.Sync()
				}
				err = errors.Join(err, file.Close())
			}
			if err == nil {
				dir, openErr := root.Open(".")
				err = openErr
				if err == nil {
					err = errors.Join(dir.Sync(), dir.Close())
				}
			}
		} else {
			file, openErr := root.Open("move-target-write")
			err = openErr
			if err == nil {
				data, err = io.ReadAll(io.LimitReader(file, limit+1))
				err = errors.Join(err, file.Close())
				if len(data) > limit {
					err = errors.Join(err, io.ErrShortBuffer)
				}
			}
		}
		err = errors.Join(err, root.Close())
		switch {
		case errors.Is(err, os.ErrNotExist):
			http.Error(w, "result absent", http.StatusNotFound)
		case errors.Is(err, os.ErrExist):
			http.Error(w, "result already exists; read it back", http.StatusConflict)
		case err != nil:
			http.Error(w, "original result is uncertain", http.StatusInternalServerError)
		default:
			_, _ = w.Write(data)
		}
	})
}
