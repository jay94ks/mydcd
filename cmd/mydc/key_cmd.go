// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/wallet"
)

// keyCommand manages the named private keys in ~/.mydc/wallet.bin. The
// wallet is created on the first create or import, and an interrupted save
// is finished before anything else.
func keyCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "key",
		Short: "Manage your private keys (the wallet)",
		Long: `Keys live in ~/.mydc/wallet.bin, encrypted with the wallet password.
The first 'key create' or 'key import' makes the wallet and asks for a new
password. Private keys are never printed.`,
		Sub: []*cli.Command{
			{
				Name:  "list",
				Short: "List keys",
				Run: func(c *cli.Context, args []string) error {
					if len(args) != 0 {
						return cli.Usagef("list takes no arguments")
					}
					return withWallet(g, c, false, func(d *wallet.Disk, _ []byte) error {
						keys, err := d.List()
						if err != nil {
							return err
						}
						return printKeys(g, c, keys)
					})
				},
			},
			{
				Name:  "create",
				Args:  "NAME",
				Short: "Make a new key",
				Run: func(c *cli.Context, args []string) error {
					name, err := keyName(args, 1)
					if err != nil {
						return err
					}
					return withWallet(g, c, true, func(d *wallet.Disk, password []byte) error {
						key, err := d.Generate(name)
						if err != nil {
							return err
						}
						if err = d.Save(password); err != nil {
							return err
						}
						return printKeys(g, c, []wallet.PublicKey{key})
					})
				},
			},
			{
				Name:  "import",
				Args:  "NAME FILE",
				Short: "Add an existing private key (PKCS#8 Ed25519 PEM)",
				Run: func(c *cli.Context, args []string) error {
					name, err := keyName(args, 2)
					if err != nil {
						return err
					}
					private, err := identity.LoadPrivateKeyFile(args[1])
					if err != nil {
						return fmt.Errorf("%s: %w", args[1], err)
					}
					defer clear(private)
					entry := wallet.Entry{Name: name}
					seed := private.Seed()
					copy(entry.Seed[:], seed)
					clear(seed)
					defer clear(entry.Seed[:])
					return withWallet(g, c, true, func(d *wallet.Disk, password []byte) error {
						changed, err := d.Put(entry)
						if err != nil {
							return err
						}
						if changed {
							if err = d.Save(password); err != nil {
								return err
							}
						}
						key, err := findKey(d, name)
						if err != nil {
							return err
						}
						return printKeys(g, c, []wallet.PublicKey{key})
					})
				},
			},
			{
				Name:  "show",
				Args:  "NAME",
				Short: "Show a key's public key",
				Run: func(c *cli.Context, args []string) error {
					name, err := keyName(args, 1)
					if err != nil {
						return err
					}
					return withWallet(g, c, false, func(d *wallet.Disk, _ []byte) error {
						key, err := findKey(d, name)
						if err != nil {
							return err
						}
						return cli.Print(c.Out, g.output.Format(), key, func() cli.Rows {
							t := cli.Rows{Header: []string{"field", "value"}}
							t.Add("name", key.Name)
							t.Add("public key", key.ID)
							return t
						})
					})
				},
			},
			{
				Name:  "passwd",
				Short: "Change the wallet password",
				Run: func(c *cli.Context, args []string) error {
					if len(args) != 0 {
						return cli.Usagef("passwd takes no arguments")
					}
					if os.Getenv("MYDC_WALLET_PASSWORD_FILE") != "" {
						return errors.New("passwd asks for the new password on the terminal; unset MYDC_WALLET_PASSWORD_FILE")
					}
					return withWallet(g, c, false, func(d *wallet.Disk, _ []byte) error {
						next, err := newWalletPassword(g, c, "New wallet password")
						if err != nil {
							return err
						}
						defer clear(next)
						if err = d.Save(next); err != nil {
							return err
						}
						fmt.Fprintln(c.Err, "Wallet password changed.")
						return nil
					})
				},
			},
		},
	}
}

// withWallet opens and unlocks the wallet. With create, a missing wallet is
// made with a new password. A save interrupted earlier is finished first.
func withWallet(g *globals, c *cli.Context, create bool, run func(*wallet.Disk, []byte) error) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	d, err := wallet.OpenDisk(home, create)
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("no wallet yet; make a key with 'mydc key create NAME'")
	}
	if err != nil {
		return err
	}
	defer d.Close()
	status, err := d.Status()
	if err != nil {
		return err
	}
	if status.Pending || status.UnpublishedCandidate {
		if err = d.Recover(false); err != nil {
			return fmt.Errorf("finishing an interrupted wallet save: %w", err)
		}
		if status, err = d.Status(); err != nil {
			return err
		}
	}
	var password []byte
	if !status.Exists {
		if !create {
			return errors.New("no wallet yet; make a key with 'mydc key create NAME'")
		}
		fmt.Fprintln(c.Err, "Creating the wallet ~/.mydc/wallet.bin.")
		if password, err = newWalletPassword(g, c, "New wallet password"); err != nil {
			return err
		}
		defer clear(password)
		if err = d.Init(password); err != nil {
			return err
		}
	} else {
		if password, err = walletPassword(g, c, "Wallet password"); err != nil {
			return err
		}
		defer clear(password)
	}
	if err = d.Unlock(password); err != nil {
		return err
	}
	return run(d, password)
}

// walletPassword reads the wallet password from MYDC_WALLET_PASSWORD_FILE,
// else from the terminal.
func walletPassword(g *globals, c *cli.Context, label string) ([]byte, error) {
	return readWalletPassword(walletFD{}, g.noInput, label, c.Err)
}

// newWalletPassword asks for a new password twice. For a new wallet a
// script gives it in MYDC_WALLET_PASSWORD_FILE.
func newWalletPassword(g *globals, c *cli.Context, label string) ([]byte, error) {
	if password, ok, err := walletPasswordFromEnv(); ok || err != nil {
		return password, err
	}
	first, err := walletPassword(g, c, label)
	if err != nil {
		return nil, err
	}
	again, err := walletPassword(g, c, "Again")
	if err != nil {
		clear(first)
		return nil, err
	}
	defer clear(again)
	if subtle.ConstantTimeCompare(first, again) != 1 {
		clear(first)
		return nil, errors.New("the passwords do not match")
	}
	return first, nil
}

func findKey(d *wallet.Disk, name string) (wallet.PublicKey, error) {
	keys, err := d.List()
	if err != nil {
		return wallet.PublicKey{}, err
	}
	for _, k := range keys {
		if k.Name == name {
			return k, nil
		}
	}
	return wallet.PublicKey{}, fmt.Errorf("no key named %s in the wallet", name)
}

func keyName(args []string, n int) (string, error) {
	if len(args) != n {
		if n == 2 {
			return "", cli.Usagef("needs a key name and a file")
		}
		return "", cli.Usagef("needs one key name")
	}
	if !cliprofile.ValidKeyName(args[0]) {
		return "", cli.Usagef("%q is not a valid key name", args[0])
	}
	return args[0], nil
}

func printKeys(g *globals, c *cli.Context, keys []wallet.PublicKey) error {
	if keys == nil {
		keys = []wallet.PublicKey{}
	}
	return cli.Print(c.Out, g.output.Format(), keys, func() cli.Rows {
		t := cli.Rows{Header: []string{"name", "public key"}}
		for _, k := range keys {
			t.Add(k.Name, k.ID)
		}
		return t
	})
}
