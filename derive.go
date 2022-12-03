package mnemonikey

import (
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/kklash/mnemonikey/pgp"
)

const (
	// KeyExpandInfoMaster is the string used as the 'info' parameter to the
	// HDKF-Expand function when generating a master key from a seed.
	KeyExpandInfoMaster = "mnemonikey master key"

	// KeyExpandInfoEncryption is the string used as the 'info' parameter to the
	// HDKF-Expand function when generating an encryption subkey from a seed.
	KeyExpandInfoEncryption = "mnemonikey encryption subkey"

	// KeyExpandInfoAuthentication is the string used as the 'info' parameter to the
	// HDKF-Expand function when generating an authentication subkey from a seed.
	KeyExpandInfoAuthentication = "mnemonikey authentication subkey"

	// KeyExpandInfoSigning is the string used as the 'info' parameter to the
	// HDKF-Expand function when generating a signing subkey from a seed.
	KeyExpandInfoSigning = "mnemonikey signing subkey"
)

// hkdfExpand expands the given seed into a key of the given size, scoped under info.
func hkdfExpand(seedBytes []byte, size int, info string) ([]byte, error) {
	keyOutput := make([]byte, size)
	keyReader := hkdf.Expand(sha256.New, seedBytes, []byte(info))
	if _, err := io.ReadFull(keyReader, keyOutput); err != nil {
		return nil, err
	}
	return keyOutput, nil
}

// derivePGPKeySet derives a pgp.KeySet by expanding the given seed using the
// HMAC-based Key Derivation Function (defined in RFC-5869) with SHA256.
//
// Sets the key's creation and expiry times to the given values.
func derivePGPKeySet(seedBytes []byte, name, email string, creation, expiry time.Time) (*pgp.KeySet, error) {
	masterKeySeed, err := hkdfExpand(seedBytes, 32, KeyExpandInfoMaster)
	if err != nil {
		return nil, fmt.Errorf("failed to derive master key from seed: %w", err)
	}
	masterKey, err := pgp.NewED25519MasterKey(masterKeySeed, creation, expiry)
	if err != nil {
		return nil, err
	}

	encryptionSubkeySeed, err := hkdfExpand(seedBytes, 32, KeyExpandInfoEncryption)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption subkey from seed: %w", err)
	}
	encryptionSubkey, err := pgp.NewCurve25519Subkey(encryptionSubkeySeed, creation, expiry, nil)
	if err != nil {
		return nil, err
	}

	authenticationSubkeySeed, err := hkdfExpand(seedBytes, 32, KeyExpandInfoAuthentication)
	if err != nil {
		return nil, fmt.Errorf("failed to derive authentication subkey from seed: %w", err)
	}
	authenticationSubkey, err := pgp.NewED25519Subkey(authenticationSubkeySeed, creation, expiry)
	if err != nil {
		return nil, err
	}

	signingSubkeySeed, err := hkdfExpand(seedBytes, 32, KeyExpandInfoSigning)
	if err != nil {
		return nil, fmt.Errorf("failed to derive signing subkey from seed: %w", err)
	}
	signingSubkey, err := pgp.NewED25519Subkey(signingSubkeySeed, creation, expiry)
	if err != nil {
		return nil, err
	}

	pgpKeySet := &pgp.KeySet{
		UserID: &pgp.UserID{
			Name:  name,
			Email: email,
		},
		MasterKey:            masterKey,
		EncryptionSubkey:     encryptionSubkey,
		AuthenticationSubkey: authenticationSubkey,
		SigningSubkey:        signingSubkey,
	}
	return pgpKeySet, nil
}
