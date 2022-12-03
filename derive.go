package mnemonikey

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/kklash/mnemonikey/pgp"
)

// keyExpandInfoMaster is the string used as the 'info' parameter to the
// HDKF-Expand function when generating a master key from a seed.
const keyExpandInfoMaster = "mnemonikey master key"

// keyExpandInfoSubkey builds the HKDF-Expand function's "info" parameter, used
// to derive a given PGP subkey based on the subkey's type and an index parameter.
func keyExpandInfoSubkey(subkeyType SubkeyType, index uint16) []byte {
	keyInfoPrefix := "mnemonikey " + subkeyType + " subkey"
	info := make([]byte, len(keyInfoPrefix)+2)
	copy(info, keyInfoPrefix)
	binary.BigEndian.PutUint16(info[len(keyInfoPrefix):], index)
	return info
}

// hkdfExpand expands the given seed into a key of the given size, scoped under info.
func hkdfExpand(seedBytes []byte, size int, info []byte) ([]byte, error) {
	keyOutput := make([]byte, size)
	keyReader := hkdf.Expand(sha256.New, seedBytes, info)
	if _, err := io.ReadFull(keyReader, keyOutput); err != nil {
		return nil, err
	}
	return keyOutput, nil
}

// derivePGPKeySet derives a pgp.KeySet by expanding the given seed using the
// HMAC-based Key Derivation Function (defined in RFC-5869) with SHA256.
//
// Sets the key's creation time to the given value. Sets the key's user ID
// and expiry time to values given in the key options.
//
// The opts struct can also provide subkey indices which will cause different subkeys
// to be generated.
func derivePGPKeySet(seedBytes []byte, creation time.Time, opts *KeyOptions) (*pgp.KeySet, error) {
	masterKeySeed, err := hkdfExpand(seedBytes, 32, []byte(keyExpandInfoMaster))
	if err != nil {
		return nil, fmt.Errorf("failed to derive master key from seed: %w", err)
	}
	masterKey, err := pgp.NewED25519MasterKey(masterKeySeed, creation, opts.Expiry)
	if err != nil {
		return nil, err
	}

	pgpKeySet := &pgp.KeySet{
		UserID: &pgp.UserID{
			Name:  opts.Name,
			Email: opts.Email,
		},
		MasterKey: masterKey,
	}

	if opts.subkeyEnabled(SubkeyTypeEncryption) {
		encKeyInfo := keyExpandInfoSubkey(SubkeyTypeEncryption, opts.EncryptionSubkeyIndex)
		encryptionSubkeySeed, err := hkdfExpand(seedBytes, 32, encKeyInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to derive encryption subkey from seed: %w", err)
		}
		pgpKeySet.EncryptionSubkey, err = pgp.NewCurve25519Subkey(encryptionSubkeySeed, creation, opts.Expiry, nil)
		if err != nil {
			return nil, err
		}
	}

	if opts.subkeyEnabled(SubkeyTypeAuthentication) {
		authKeyInfo := keyExpandInfoSubkey(SubkeyTypeAuthentication, opts.AuthenticationSubkeyIndex)
		authenticationSubkeySeed, err := hkdfExpand(seedBytes, 32, authKeyInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to derive authentication subkey from seed: %w", err)
		}
		pgpKeySet.AuthenticationSubkey, err = pgp.NewED25519Subkey(authenticationSubkeySeed, creation, opts.Expiry)
		if err != nil {
			return nil, err
		}
	}

	if opts.subkeyEnabled(SubkeyTypeSigning) {
		sigKeyInfo := keyExpandInfoSubkey(SubkeyTypeSigning, opts.SigningSubkeyIndex)
		signingSubkeySeed, err := hkdfExpand(seedBytes, 32, sigKeyInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to derive signing subkey from seed: %w", err)
		}
		pgpKeySet.SigningSubkey, err = pgp.NewED25519Subkey(signingSubkeySeed, creation, opts.Expiry)
		if err != nil {
			return nil, err
		}
	}

	return pgpKeySet, nil
}
