package mnemonikey

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"testing"
	"time"
)

type GPG struct {
	HomeDir string
}

func (gpg *GPG) Run(stdin io.Reader, args ...string) ([]byte, error) {
	args = append(
		[]string{
			"--homedir", gpg.HomeDir,
			"--no-tty", "--yes", "--quiet",
			"--trust-model", "always",
		},
		args...,
	)
	cmd := exec.Command("gpg", args...)
	cmd.Stdin = stdin
	stdout, err := cmd.Output()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return nil, fmt.Errorf("%w: %s", err, exitErr.Stderr)
	} else if err != nil {
		return nil, err
	}

	return stdout, nil
}

func NewGPG(homeDir string) (*GPG, error) {
	gpg := &GPG{
		HomeDir: homeDir,
	}
	if err := os.Chmod(homeDir, 0700); err != nil {
		return nil, err
	}
	// build the home directory
	if _, err := gpg.Run(nil, "-k"); err != nil {
		return nil, err
	}
	return gpg, nil
}

func TestMnemonikey(t *testing.T) {
	gpg, err := NewGPG(t.TempDir())
	if err != nil {
		t.Fatalf("failed to instantiate GPG: %s", err)
	}

	recoveredGPG, err := NewGPG(t.TempDir())
	if err != nil {
		t.Fatalf("failed to instantiate temporary GPG: %s", err)
	}

	seed, err := GenerateSeed(rand.New(rand.NewSource(0)))
	if err != nil {
		t.Fatalf("failed to generate seed: %s", err)
	}

	now := time.Unix(1668576000, 0)
	fingerprint := "1645C5A88E4F3DCE2F377B40448CD7DD554FFBCB"
	keyOpts := &KeyOptions{
		Name:  "username",
		Email: "user@domain.com",
	}

	mnk, err := New(seed, now, keyOpts)
	if err != nil {
		t.Fatalf("failed to derive Mnemonikey: %s", err)
	}

	words, err := mnk.EncodeMnemonic()
	if err != nil {
		t.Fatalf("failed to encode key as mnemonic: %s", err)
	}

	recoveredKey, err := Recover(words, keyOpts)
	if err != nil {
		t.Fatalf("failed to derive recovered Mnemonikey: %s", err)
	}

	t.Run("fingerprint matches", func(t *testing.T) {
		if actualFpr := fmt.Sprintf("%X", mnk.FingerprintV4()); actualFpr != fingerprint {
			t.Fatalf("fingerprint does not match\nWanted %s\nGot    %s", fingerprint, actualFpr)
		}
		if actualFpr := fmt.Sprintf("%X", recoveredKey.FingerprintV4()); actualFpr != fingerprint {
			t.Fatalf("recovered key fingerprint does not match\nWanted %s\nGot    %s", fingerprint, actualFpr)
		}
	})

	t.Run("exporting to OpenPGP and importing into GPG", func(t *testing.T) {
		gpgs := []*GPG{gpg, recoveredGPG}

		for i, kp := range []*Mnemonikey{mnk, recoveredKey} {
			gpg := gpgs[i]
			description := "Mnemonikey"
			if i == 1 {
				description = "recovered " + description
			}

			keyPackets, err := kp.EncodePGP(nil)
			if err != nil {
				t.Fatalf("failed to encode %s as OpenPGP packets: %s", description, err)
			}
			if _, err := gpg.Run(bytes.NewReader(keyPackets), "--import"); err != nil {
				t.Fatalf("failed to import %s to gpg: %s", description, err)
			}

			privKeyListOutput, err := gpg.Run(nil, "--with-colons", "-K")
			if err != nil {
				t.Fatalf("failed to run GPG: %s", err)
			}
			if !bytes.Contains(privKeyListOutput, []byte(fingerprint)) {
				t.Fatalf(
					"expected to find %s fingerprint %q in gpg --with-colons -K output: %s",
					description, fingerprint, privKeyListOutput,
				)
			}
		}
	})

	t.Run("signatures", func(t *testing.T) {
		message := []byte("message to sign")
		signature, err := recoveredGPG.Run(bytes.NewReader(message), "-u", keyOpts.Name, "--sign")
		if err != nil {
			t.Fatalf("failed to sign message with recovered key: %s", err)
		}
		if _, err := gpg.Run(bytes.NewReader(signature), "--verify"); err != nil {
			t.Fatalf("failed to verify signature made by recovered key, using original key: %s", err)
		}
	})

	t.Run("encryption", func(t *testing.T) {
		plaintext := []byte("original message")
		encryptedMessage, err := gpg.Run(
			bytes.NewReader(plaintext),
			"--recipient", keyOpts.Name,
			"--encrypt",
		)
		if err != nil {
			t.Fatalf("failed to encrypt message: %s", err)
		}

		decrypted, err := recoveredGPG.Run(bytes.NewReader(encryptedMessage), "--decrypt")
		if err != nil {
			t.Fatalf("failed to decrypt encrypted message with recovered key: %s", err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("decrypted message doesn't match\nWanted %q\nGot    %q", plaintext, decrypted)
		}
	})

	t.Run("checksum in recovery phrase detects errors", func(t *testing.T) {
		wordsBad := append([]string{}, words...)
		wordsBad[4] = "hurt"

		if _, err := Recover(wordsBad, keyOpts); !errors.Is(err, ErrInvalidChecksum) {
			t.Fatalf("expected to get ErrInvalidChecksum when mnemonic was corrupted, got: %s", err)
		}
	})
}
