// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

var errSpoolReopenUpdate = errors.New("injected spool update failure")

type spoolReopenTransactions struct {
	Transactions
	updates      int
	fail         bool
	beforeUpdate func() error
}

func (d *spoolReopenTransactions) Update(edit func(*bolt.Tx) error) error {
	d.updates++
	if before := d.beforeUpdate; before != nil {
		d.beforeUpdate = nil
		if err := before(); err != nil {
			return err
		}
	}
	if d.fail {
		return errSpoolReopenUpdate
	}
	return d.Transactions.Update(edit)
}

func TestSpoolDurableReopenAndBeginNeedNoUpdate(t *testing.T) {
	raw := bytes.Repeat([]byte{31}, PartBytes+9)
	spool, scope, root, db := openTestSpool(t, raw)
	_, key := testScope(int64(len(raw)), sha256.Sum256(raw))
	ctx := context.Background()
	if err := spool.Begin(ctx, scope); err != nil {
		t.Fatal(err)
	}
	part, err := spool.Put(ctx, scope, 0, raw[:PartBytes], key)
	if err != nil {
		t.Fatal(err)
	}
	before, err := spool.header(scope)
	if err != nil {
		t.Fatal(err)
	}
	writes := &spoolReopenTransactions{Transactions: db, fail: true}
	reopened, err := OpenSpool(int(root.Fd()), scope.Root, writes)
	if err != nil {
		t.Fatal("durable identity required a write", err)
	}
	defer reopened.Close()
	if err := reopened.Begin(ctx, scope); err != nil {
		t.Fatal("durable header/inode required a write", err)
	}
	again, err := reopened.RecoverPart(ctx, scope, 0, part.Digest, key)
	if err != nil || !bytes.Equal(again.Signature, part.Signature) || writes.updates != 0 {
		t.Fatal("read-only recovery changed receipt or wrote evidence", err, writes.updates)
	}
	if receipt, err := reopened.Put(ctx, scope, 1, raw[PartBytes:], key); !errors.Is(err, errSpoolReopenUpdate) || len(receipt.Signature) != 0 {
		t.Fatal("new part bypassed durable intent", receipt, err)
	}
	if writes.updates != 1 {
		t.Fatal("new part did not attempt its original transaction", writes.updates)
	}
	after, err := reopened.header(scope)
	if err != nil || after != before {
		t.Fatal("failed part changed header", after, err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		if reopened.bucket(tx, scope).Get(partKey(1)) != nil {
			t.Error("failed part created intent evidence")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	file, err := reopened.file(after, false)
	if err != nil {
		t.Fatal(err)
	}
	stat, err := file.Stat()
	_ = file.Close()
	if err != nil || stat.Size() != PartBytes {
		t.Fatal("failed intent wrote native bytes", stat, err)
	}

	other := scope
	other.Upload = "new-header"
	if err := reopened.Begin(ctx, other); !errors.Is(err, ErrStorage) {
		t.Fatal("new header bypassed transaction failure", err)
	}
	if _, err := os.Stat(filepath.Join(root.Name(), ".mydc-imagebuild", scopeName(other)+".zip")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed new header created native file", err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		if reopened.bucket(tx, other) != nil {
			t.Error("failed new header created scope bucket")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolMissingIdentityStillRequiresDurableUpdate(t *testing.T) {
	spool, scope, root, db := openTestSpool(t, []byte("archive"))
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(spoolBucket).Bucket(spool.key).Delete([]byte("identity"))
	}); err != nil {
		t.Fatal(err)
	}
	writes := &spoolReopenTransactions{Transactions: db, fail: true}
	if reopened, err := OpenSpool(int(root.Fd()), scope.Root, writes); !errors.Is(err, ErrStorage) || reopened != nil || writes.updates != 1 {
		t.Fatal("missing identity accepted without commit", reopened, err, writes.updates)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(spoolBucket).Bucket(spool.key).Get([]byte("identity")) != nil {
			t.Error("failed commit created identity evidence")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root.Name(), ".mydc-imagebuild"))
	if err != nil || len(entries) != 0 {
		t.Fatal("failed identity created an artifact", entries, err)
	}
}

func TestSpoolReopenRejectsChangedIdentityAndOriginalInodeWithoutWrites(t *testing.T) {
	t.Run("identity", func(t *testing.T) {
		spool, scope, root, db := openTestSpool(t, []byte("archive"))
		if err := db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(spoolBucket).Bucket(spool.key).Put([]byte("identity"), []byte("corrupt identity"))
		}); err != nil {
			t.Fatal(err)
		}
		writes := &spoolReopenTransactions{Transactions: db, fail: true}
		if reopened, err := OpenSpool(int(root.Fd()), scope.Root, writes); !errors.Is(err, ErrStorage) || reopened != nil || writes.updates != 0 {
			t.Fatal("corrupt identity rewritten or accepted", err, writes.updates)
		}
	})
	t.Run("directory", func(t *testing.T) {
		_, scope, root, db := openTestSpool(t, []byte("archive"))
		path := filepath.Join(root.Name(), ".mydc-imagebuild")
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		writes := &spoolReopenTransactions{Transactions: db, fail: true}
		if reopened, err := OpenSpool(int(root.Fd()), scope.Root, writes); !errors.Is(err, ErrStorage) || reopened != nil || writes.updates != 0 {
			t.Fatal("replacement directory accepted", err, writes.updates)
		}
	})
	t.Run("file", func(t *testing.T) {
		spool, scope, root, db := openTestSpool(t, []byte("archive"))
		if err := spool.Begin(context.Background(), scope); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root.Name(), ".mydc-imagebuild", scopeName(scope)+".zip")
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		writes := &spoolReopenTransactions{Transactions: db, fail: true}
		spool.db = writes
		if err := spool.Begin(context.Background(), scope); !errors.Is(err, ErrStorage) || writes.updates != 0 {
			t.Fatal("replacement inode accepted or evidence rewritten", err, writes.updates)
		}
	})
}

func TestSpoolInitializersRecheckIdentityAndHeaderInUpdate(t *testing.T) {
	t.Run("identity", func(t *testing.T) {
		for _, corrupt := range []bool{false, true} {
			t.Run(map[bool]string{false: "same", true: "changed"}[corrupt], func(t *testing.T) {
				spool, scope, root, db := openTestSpool(t, []byte("archive"))
				var original []byte
				if err := db.Update(func(tx *bolt.Tx) error {
					b := tx.Bucket(spoolBucket).Bucket(spool.key)
					original = bytes.Clone(b.Get([]byte("identity")))
					return b.Delete([]byte("identity"))
				}); err != nil {
					t.Fatal(err)
				}
				concurrent := original
				if corrupt {
					concurrent = []byte("another identity")
				}
				writes := &spoolReopenTransactions{Transactions: db, beforeUpdate: func() error {
					return db.Update(func(tx *bolt.Tx) error {
						return tx.Bucket(spoolBucket).Bucket(spool.key).Put([]byte("identity"), concurrent)
					})
				}}
				reopened, err := OpenSpool(int(root.Fd()), scope.Root, writes)
				if corrupt {
					if !errors.Is(err, ErrStorage) || reopened != nil {
						t.Fatal("concurrent different identity overwritten", err)
					}
				} else {
					if err != nil {
						t.Fatal("same concurrent identity rejected", err)
					}
					defer reopened.Close()
				}
				if err := db.View(func(tx *bolt.Tx) error {
					if !bytes.Equal(tx.Bucket(spoolBucket).Bucket(spool.key).Get([]byte("identity")), concurrent) {
						t.Error("concurrent identity changed")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	})
	t.Run("header", func(t *testing.T) {
		raw := []byte("archive")
		spool, scope, root, db := openTestSpool(t, raw)
		_, key := testScope(int64(len(raw)), sha256.Sum256(raw))
		var concurrent []byte
		writes := &spoolReopenTransactions{Transactions: db, beforeUpdate: func() error {
			if err := spool.Begin(context.Background(), scope); err != nil {
				return err
			}
			if _, err := spool.Put(context.Background(), scope, 0, raw, key); err != nil {
				return err
			}
			return db.View(func(tx *bolt.Tx) error {
				concurrent = bytes.Clone(spool.bucket(tx, scope).Get(spoolHeader))
				return nil
			})
		}}
		reopened, err := OpenSpool(int(root.Fd()), scope.Root, writes)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		if err := reopened.Begin(context.Background(), scope); err != nil || writes.updates != 1 {
			t.Fatal("concurrent original header rejected", err, writes.updates)
		}
		if err := db.View(func(tx *bolt.Tx) error {
			if !bytes.Equal(reopened.bucket(tx, scope).Get(spoolHeader), concurrent) {
				t.Error("concurrent header/inode/part count reset")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("changed-header", func(t *testing.T) {
		spool, scope, _, db := openTestSpool(t, []byte("archive"))
		changed := scope
		changed.Creator = "another-user"
		raw, err := json.Marshal(localUpload{Scope: changed})
		if err != nil {
			t.Fatal(err)
		}
		writes := &spoolReopenTransactions{Transactions: db, beforeUpdate: func() error {
			return db.Update(func(tx *bolt.Tx) error {
				b, err := tx.Bucket(spoolBucket).Bucket(spool.key).CreateBucket([]byte(scopeName(scope)))
				if err != nil {
					return err
				}
				return b.Put(spoolHeader, raw)
			})
		}}
		spool.db = writes
		if err := spool.Begin(context.Background(), scope); !errors.Is(err, ErrStorage) {
			t.Fatal("concurrent different header accepted", err)
		}
		if err := db.View(func(tx *bolt.Tx) error {
			if !bytes.Equal(spool.bucket(tx, scope).Get(spoolHeader), raw) {
				t.Error("concurrent different header overwritten")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
