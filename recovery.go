package mnemonikey

import (
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"time"

	"github.com/kklash/mnemonikey/mnemonic"
)

// ErrInvalidChecksum is returned when decoding a mnemonic fails due
// to a checksum mismatch.
var ErrInvalidChecksum = errors.New("failed to validate checksum embedded in mnemonic phrase")

// RecoverKeyPair decodes a seed and creation offset from the given recovery mnemonic and
// re-derives its child PGP key.
//
// The given name and email must be the same as was used to originally generate the key,
// otherwise the key fingerprint will not match.
//
// If the original key's user ID is not a standard RFC-2822 mail name-addr format (NAME <EMAIL>),
// then simply provide the entire user ID as the name parameter, and leave the email parameter
// empty.
func RecoverKeyPair(words []string, name, email string, expiry time.Time) (*DeterministicKeyPair, error) {
	seed, creationOffset, err := DecodeMnemonic(words)
	if err != nil {
		return nil, err
	}

	keyPair, err := NewDeterministicKeyPair(seed, name, email, creationOffset, expiry)
	if err != nil {
		return nil, fmt.Errorf("failed to recover key pair from decoded mnemonic: %w", err)
	}

	return keyPair, nil
}

// DecodeMnemonic decodes a recovery mnemonic into the embedded Seed data
// and key creation timestamp.
func DecodeMnemonic(words []string) (seed *Seed, creation time.Time, err error) {
	indices, err := mnemonic.DecodeMnemonic(words)
	if err != nil {
		return
	}

	payloadInt, err := mnemonic.DecodeIndices(indices)
	if err != nil {
		return
	}

	// Shift off checksum from lowest-order ChecksumBitCount bits
	expectedChecksum := uint32(new(big.Int).And(payloadInt, big.NewInt(int64((1<<ChecksumBitCount)-1))).Uint64())
	payloadInt.Rsh(payloadInt, ChecksumBitCount)

	// Confirm checksum is correct.
	payloadBitCount := mnemonic.BitsPerWord*uint(len(words)) - ChecksumBitCount
	payloadBytes := payloadInt.FillBytes(make([]byte, (payloadBitCount+7)/8))
	checksum := ^crc32.Checksum(payloadBytes, checksumTable)
	if checksum != expectedChecksum {
		err = ErrInvalidChecksum
		return
	}

	// Determine key creation time from next lowest-order CreationOffsetBitCount bits
	creationOffset := new(big.Int).And(payloadInt, big.NewInt(int64((1<<CreationOffsetBitCount)-1))).Uint64()
	creation = EpochStart.Add(time.Duration(creationOffset) * EpochIncrement)
	payloadInt.Rsh(payloadInt, CreationOffsetBitCount)

	// Remaining bits are all seed data
	seedEntropyBitCount := payloadBitCount - CreationOffsetBitCount
	seed = NewSeed(payloadInt, seedEntropyBitCount)

	return
}
