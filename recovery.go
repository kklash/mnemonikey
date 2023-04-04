package mnemonikey

import (
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"strings"
	"time"

	"github.com/kklash/mnemonikey/mnemonic"
	"github.com/kklash/wordlist4096"
)

// ErrInvalidChecksum is returned when decoding a mnemonic fails due
// to a checksum mismatch.
var ErrInvalidChecksum = errors.New("failed to validate checksum embedded in mnemonic phrase")

// ErrInvalidWordCount is returned when decoding a mnemonic recovery
// phrase whose word count is not MnemonicSize.
var ErrInvalidWordCount = fmt.Errorf("mnemonics must be %d words long", MnemonicSize)

// Recover decodes a seed and creation offset from the given recovery mnemonic and
// re-derives its child PGP keys.
//
// If the original key's user ID is not a standard RFC-2822 mail name-addr format (NAME <EMAIL>),
// then simply provide the entire user ID as the name parameter, and leave the email parameter
// empty.
func Recover(words []string, opts *KeyOptions) (*Mnemonikey, error) {
	seed, creation, err := DecodeMnemonic(words)
	if err != nil {
		return nil, err
	}

	mnk, err := New(seed, creation, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to recover key from decoded mnemonic: %w", err)
	}

	return mnk, nil
}

// DecodeMnemonic decodes a recovery mnemonic into the embedded Seed data
// and key creation timestamp.
func DecodeMnemonic(words []string) (seed *Seed, creation time.Time, err error) {
	if len(words) != int(MnemonicSize) {
		err = ErrInvalidWordCount
		return
	}
	indices, err := mnemonic.DecodeWords(words)
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
	checksum := checksumMask & crc32.ChecksumIEEE(payloadBytes)
	if checksum != expectedChecksum {
		err = ErrInvalidChecksum
		return
	}

	// Determine key creation time from next lowest-order CreationOffsetBitCount bits
	creationOffset := new(big.Int).And(payloadInt, big.NewInt(int64((1<<CreationOffsetBitCount)-1))).Uint64()
	creation = EpochStart.Add(time.Duration(creationOffset) * EpochIncrement)
	payloadInt.Rsh(payloadInt, CreationOffsetBitCount)

	// Determine seed entropy integer
	seedInt := new(big.Int).And(payloadInt, entropyMask)
	payloadInt.Rsh(payloadInt, EntropyBitCount)

	// Remaining bits are the version number.
	version := uint(payloadInt.Uint64())

	// NewSeed will return ErrUnsupportedSeedVersion if the version number is unsupported.
	seed, err = NewSeed(version, seedInt)
	return
}

// ParseVersion parses the version number encoded in first word of the recovery phrase. Returns
// mnemonic.ErrInvalidWord if the word is not in the word list. Returns ErrUnsupportedSeedVersion
// if the version number is greater than VersionLatest.
//
// This can be used to inform a user ahead of time if the user's mnemonic recovery phrase is
// not supported by this version of the Mnemonikey library, thus saving them from entering
// the whole phrase in needlessly.
func ParseVersion(firstWord string) (version uint, err error) {
	index, ok := wordlist4096.WordMap[strings.ToLower(firstWord)]
	if !ok {
		return 0, mnemonic.ErrInvalidWord
	}

	version = uint(index) >> (wordlist4096.BitsPerWord - VersionBitCount)
	err = checkSeedVersion(version)
	return
}
