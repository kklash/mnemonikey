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

func TestDeterministicKeyPair(t *testing.T) {
	gpg, err := NewGPG(t.TempDir())
	if err != nil {
		t.Fatalf("failed to instantiate GPG: %s", err)
	}

	recoveredGPG, err := NewGPG(t.TempDir())
	if err != nil {
		t.Fatalf("failed to instantiate temporary GPG: %s", err)
	}

	seed, err := GenerateSeed(rand.New(rand.NewSource(0)), MinMnemonicSize)
	if err != nil {
		t.Fatalf("failed to generate seed: %s", err)
	}

	name := "username"
	email := "user@domain.com"
	now := time.Unix(1668576000, 0)
	fingerprint := "FE4327E47DFC189120437CA59EC88AAE8DE963F8"

	keyPair, err := NewDeterministicKeyPair(seed, name, email, now, time.Time{})
	if err != nil {
		t.Fatalf("failed to derive DeterministicKeyPair: %s", err)
	}

	words, err := keyPair.EncodeMnemonic()
	if err != nil {
		t.Fatalf("failed to encode key pair mnemonic: %s", err)
	}

	recoveredKeyPair, err := RecoverKeyPair(words, name, email, time.Time{})
	if err != nil {
		t.Fatalf("failed to derive recovered DeterministicKeyPair: %s", err)
	}

	t.Run("fingerprint matches", func(t *testing.T) {
		if actualFpr := fmt.Sprintf("%X", keyPair.FingerprintV4()); actualFpr != fingerprint {
			t.Fatalf("fingerprint does not match\nWanted %s\nGot    %s", fingerprint, actualFpr)
		}
		if actualFpr := fmt.Sprintf("%X", recoveredKeyPair.FingerprintV4()); actualFpr != fingerprint {
			t.Fatalf("recovered key fingerprint does not match\nWanted %s\nGot    %s", fingerprint, actualFpr)
		}
	})

	t.Run("exporting to OpenPGP and importing into GPG", func(t *testing.T) {
		gpgs := []*GPG{gpg, recoveredGPG}
		keyPairs := []*DeterministicKeyPair{keyPair, recoveredKeyPair}

		for i, kp := range keyPairs {
			gpg := gpgs[i]
			description := "DeterministicKeyPair"
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
		signature, err := recoveredGPG.Run(bytes.NewReader(message), "-u", name, "--sign")
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
			"--recipient", name,
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

		if _, err := RecoverKeyPair(wordsBad, name, email, time.Time{}); !errors.Is(err, ErrInvalidChecksum) {
			t.Fatalf("expected to get ErrInvalidChecksum when mnemonic was corrupted, got: %s", err)
		}
	})
}
