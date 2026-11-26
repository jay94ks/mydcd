// SPDX-License-Identifier: Apache-2.0

// Package storage supplies module-owned, synchronous bbolt transactions.
package storage

import (
	"errors"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"time"
)

var ErrMissing = errors.New("record not found")

type DB struct{ db *bolt.DB }

// View/Update lend a synchronous transaction to module-owned native adapters.
// The callback must not retain a Tx/Bucket/value after it returns, or close the
// borrowed transaction/database. This does not open a second database.
func (d *DB) View(fn func(*bolt.Tx) error) error   { return d.db.View(fn) }
func (d *DB) Update(fn func(*bolt.Tx) error) error { return d.db.Update(fn) }

var records = []byte("schema-1")

// OpenReadOnly never creates a directory/file/bucket or commits a bbolt meta
// page. Offline preparation must preserve the original source DB bytes.
func OpenReadOnly(path string) (*DB, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("readonly database must be an existing private regular file")
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	err = db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(records) == nil {
			return errors.New("readonly database is missing its original schema bucket")
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &DB{db}, nil
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("database must be a private regular file")
	}
	b, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	err = b.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucketIfNotExists(records); return err })
	if err != nil {
		_ = b.Close()
		return nil, err
	}
	return &DB{b}, nil
}
func (d *DB) Close() error { return d.db.Close() }

// Sync confirms durability of an already stored immutable artifact on explicit
// recovery; reading an entry alone does not settle a prior sync error.
func (d *DB) Sync() error { return d.db.Sync() }

func (d *DB) GetBounded(key string, maxBytes int) ([]byte, error) {
	if maxBytes < 1 {
		return nil, errors.New("invalid read budget")
	}
	var value []byte
	err := d.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(records).Get([]byte(key))
		if b == nil {
			return ErrMissing
		}
		if len(b) > maxBytes {
			return errors.New("record read budget exceeded")
		}
		value = append([]byte(nil), b...)
		return nil
	})
	return value, err
}

// SizesBounded checks a blob namespace without copying blob values. Owners use
// this to reject orphan/missing records during recovery and quota accounting.
func (d *DB) SizesBounded(prefix string, maxRecords, maxKeyBytes int) (map[string]uint64, error) {
	if maxRecords < 1 || maxKeyBytes < 1 {
		return nil, errors.New("invalid index budget")
	}
	result := map[string]uint64{}
	err := d.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(records).Cursor()
		remaining := maxKeyBytes
		for k, v := c.Seek([]byte(prefix)); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == prefix; k, v = c.Next() {
			if len(result) >= maxRecords || len(k) > remaining {
				return errors.New("blob index budget exceeded")
			}
			remaining -= len(k)
			result[string(k)] = uint64(len(v))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ScanBounded reads only a bounded metadata namespace, not artifact data. It
// stops before allocating a value beyond either budget.
func (d *DB) ScanBounded(prefix string, maxRecords, maxBytes int) (map[string][]byte, error) {
	if maxRecords < 1 || maxBytes < 1 {
		return nil, errors.New("invalid scan budget")
	}
	result := map[string][]byte{}
	err := d.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(records).Cursor()
		remaining := maxBytes
		for k, v := c.Seek([]byte(prefix)); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == prefix; k, v = c.Next() {
			if len(result) >= maxRecords || len(k) > remaining || len(v) > remaining-len(k) {
				return errors.New("metadata scan budget exceeded")
			}
			remaining -= len(k) + len(v)
			result[string(k)] = append([]byte(nil), v...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
func (d *DB) Get(key string) ([]byte, error) {
	var value []byte
	err := d.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(records).Get([]byte(key))
		if b == nil {
			return ErrMissing
		}
		value = append([]byte(nil), b...)
		return nil
	})
	return value, err
}

// Write updates all records together; nil means delete. bbolt sync remains on.
func (d *DB) Write(values map[string][]byte) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(records)
		for key, value := range values {
			var err error
			if value == nil {
				err = b.Delete([]byte(key))
			} else {
				err = b.Put([]byte(key), value)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}
func (d *DB) Scan(prefix string) (map[string][]byte, error) {
	result := map[string][]byte{}
	err := d.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(records).Cursor()
		for k, v := c.Seek([]byte(prefix)); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == prefix; k, v = c.Next() {
			result[string(k)] = append([]byte(nil), v...)
		}
		return nil
	})
	return result, err
}
