package mnemonikey

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"os/exec"
	"reflect"
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

	seed, err := GenerateSeed(mrand.New(mrand.NewSource(0)))
	if err != nil {
		t.Fatalf("failed to generate seed: %s", err)
	}

	now := time.Unix(1673800000, 0)
	fingerprint := "149EE476771DBD4E19D1FB0FC1A9CE93575CA7FA"
	encryptionSubkeyFingerprint := "7DDB15BC71C3ABBC1B875C828CBC9D2E12D69C81"
	keyOpts := &KeyOptions{
		Name:    "username",
		Email:   "user@domain.com",
		Subkeys: []SubkeyType{SubkeyTypeEncryption, SubkeyTypeSigning},
	}

	mnk, err := New(seed, now, keyOpts)
	if err != nil {
		t.Fatalf("failed to derive Mnemonikey: %s", err)
	}

	t.Run("fingerprint matches", func(t *testing.T) {
		if actualFpr := fmt.Sprintf("%X", mnk.FingerprintV4()); actualFpr != fingerprint {
			t.Fatalf("fingerprint does not match\nWanted %s\nGot    %s", fingerprint, actualFpr)
		}

		actualEncryptionSubkeyFingerprint := fmt.Sprintf("%X", mnk.SubkeyFingerprintV4(SubkeyTypeEncryption))
		if actualEncryptionSubkeyFingerprint != encryptionSubkeyFingerprint {
			t.Fatalf(
				"encryption subkey fingerprint does not match\nWanted %s\nGot    %s",
				encryptionSubkeyFingerprint, actualEncryptionSubkeyFingerprint,
			)
		}
	})

	recoveredKeys := []*Mnemonikey{}

	t.Run("encode and recover plaintext mnemonic", func(t *testing.T) {
		words, err := mnk.EncodeMnemonicPlaintext()
		if err != nil {
			t.Fatalf("failed to encode key as plaintext mnemonic: %s", err)
		}

		recoveredKey, err := RecoverPlaintext(words, keyOpts)
		if err != nil {
			t.Fatalf("failed to derive recovered plaintext Mnemonikey: %s", err)
		}

		recoveredKeys = append(recoveredKeys, recoveredKey)
	})

	t.Run("encode and recover encrypted mnemonic", func(t *testing.T) {
		password := []byte("password123")
		words, err := mnk.EncodeMnemonicEncrypted(password, rand.Reader)
		if err != nil {
			t.Fatalf("failed to encode key as encrypted mnemonic: %s", err)
		}

		recoveredKey, err := RecoverEncrypted(words, password, keyOpts)
		if err != nil {
			t.Fatalf("failed to derive recovered encrypted Mnemonikey: %s", err)
		}

		recoveredKeys = append(recoveredKeys, recoveredKey)
	})

	t.Run("recovered key fingerprint matches", func(t *testing.T) {
		for _, recoveredKey := range recoveredKeys {
			if actualFpr := fmt.Sprintf("%X", recoveredKey.FingerprintV4()); actualFpr != fingerprint {
				t.Fatalf("recovered key fingerprint does not match\nWanted %s\nGot    %s", fingerprint, actualFpr)
			}

			recoveredEncryptionSubkeyFingerprint := fmt.Sprintf("%X", recoveredKey.SubkeyFingerprintV4(SubkeyTypeEncryption))
			if recoveredEncryptionSubkeyFingerprint != encryptionSubkeyFingerprint {
				t.Fatalf(
					"recovered encryption subkey fingerprint does not match\nWanted %s\nGot    %s",
					encryptionSubkeyFingerprint, recoveredEncryptionSubkeyFingerprint,
				)
			}
		}
	})

	t.Run("subkey indices can be incremented", func(t *testing.T) {
		words, err := mnk.EncodeMnemonicPlaintext()
		if err != nil {
			t.Fatalf("failed to encode key as plaintext mnemonic: %s", err)
		}

		incrementedKey, err := RecoverPlaintext(words, &KeyOptions{
			Name:                  keyOpts.Name,
			Email:                 keyOpts.Email,
			EncryptionSubkeyIndex: 1,
		})
		if err != nil {
			t.Fatalf("failed to derive recovered Mnemonikey with incremented encryption subkey: %s", err)
		}

		expectedFingerprint := "696F446E6C6AF70FD04CA4BC4DF250AD768F1D6D"
		actualFpr := fmt.Sprintf("%X", incrementedKey.SubkeyFingerprintV4(SubkeyTypeEncryption))
		if actualFpr != expectedFingerprint {
			t.Fatalf(
				"incremented encryption subkey fingerprint does not match\nWanted %s\nGot    %s",
				expectedFingerprint, actualFpr,
			)
		}
	})

	t.Run("returns subkey types", func(t *testing.T) {
		keyTypes := mnk.SubkeyTypes()
		if !reflect.DeepEqual(keyTypes, keyOpts.Subkeys) {
			t.Errorf("SubkeyTypes didn't return expected subkey types")
		}
	})

	t.Run("exporting to OpenPGP and importing into GPG", func(t *testing.T) {
		gpgs := []*GPG{gpg, recoveredGPG}

		for i, kp := range append([]*Mnemonikey{mnk}, recoveredKeys[0]) {
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
		words, err := mnk.EncodeMnemonicPlaintext()
		if err != nil {
			t.Fatalf("failed to encode key as plaintext mnemonic: %s", err)
		}

		wordsBad := append([]string{}, words...)
		wordsBad[4] = "hurt"

		if _, err := RecoverPlaintext(wordsBad, keyOpts); !errors.Is(err, ErrInvalidChecksum) {
			t.Fatalf("expected to get ErrInvalidChecksum when mnemonic was corrupted, got: %s", err)
		}
	})
}
