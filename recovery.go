package mnemonikey

import (
	"fmt"
	"math/big"
	"time"

	"github.com/kklash/mnemonikey/mnemonic"
)

// RecoverKeyPair decodes a seed and birthday from the given recovery mnemonic and
// re-derives its child PGP key.
//
// The given name and email must be the same as was used to originally generate the key,
// otherwise the key fingerprint will not match.
//
// If the original key's user ID is not a standard RFC-2822 mail name-addr format (NAME <EMAIL>),
// then simply provide the entire user ID as the name parameter, and leave the email parameter
// empty.
func RecoverKeyPair(words []string, name, email string, expiry time.Time) (*DeterministicKeyPair, error) {
	seed, birthday, err := DecodeMnemonic(words)
	if err != nil {
		return nil, err
	}

	keyPair, err := NewDeterministicKeyPair(seed, name, email, birthday, expiry)
	if err != nil {
		return nil, fmt.Errorf("failed to recover key pair from decoded mnemonic: %w", err)
	}

	return keyPair, nil
}

// DecodeMnemonic decodes a recovery mnemonic into the embedded Seed data
// and key birthday.
func DecodeMnemonic(words []string) (seed *Seed, birthday time.Time, err error) {
	indices, err := mnemonic.DecodeMnemonic(words)
	if err != nil {
		return
	}

	payloadInt, err := mnemonic.DecodeIndices(indices)
	if err != nil {
		return
	}

	// Determine key birthday from lowest trailing BirthdayBitCount bits
	birthdayOffset := new(big.Int).And(payloadInt, big.NewInt(int64((1<<BirthdayBitCount)-1))).Int64()
	birthday = EpochStart.Add(time.Duration(birthdayOffset) * EpochIncrement)
	payloadInt.Rsh(payloadInt, BirthdayBitCount)

	// Remaining bits are all seed data
	seedEntropyBitCount := uint(len(words))*mnemonic.BitsPerWord - BirthdayBitCount
	seed = NewSeed(payloadInt, seedEntropyBitCount)

	return
}
