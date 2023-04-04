package mnemonikey

import (
	"errors"
	"fmt"

	"github.com/kklash/mnemonikey/mnemonic"
)

// ErrInvalidEraNumber is returned when an unknown era number was used to
// construct a seed.
var ErrInvalidEraNumber = errors.New("unsupported seed era number")

// ErrInvalidVersionNumber is returned when decoding a mnemonic recovery phrase
// which contains an unknown version number. Perhaps such a phrase might have been
// encoded using a newer version of mnemonikey.
var ErrInvalidVersionNumber = errors.New("invalid version number in recovery phrase")

// Era represents an internal version number which mnemonikey uses to identify how PGP keys should
// be derived from a parsed recovery phrase. MnemonicVersion numbers map many-to-one into Era numbers.
//
// Era numbers and MnemonicVersion numbers are a subtle distinction. Era numbers
// are internal to mnemonikey - they are never exported in the recovery phrase.
// MnemonicVersion numbers map (many-to-one) to Era numbers. More than one version
// might use the same era. Recovery phrases whose versions share an era
// also share an identical procedure to derive keys after parsing, but the
// phrases themselves might be interpreted differently during recovery.
type Era int

func (era Era) check() error {
	if era > EraLatest || era < 0 {
		return fmt.Errorf("%w: %d", ErrInvalidEraNumber, era)
	}
	return nil
}

// MnemonicVersion represents a version number encoded into mnemonikey recovery phrases. A MnemonicVersion
// number can have many meanings to a mnemonikey decoder, but generally it should be used to
// define how to parse a mnemonikey backup and which Era should be used to recover the PGP keys
// from the seed encoded therein.
//
// MnemonicVersion 0 implies an era 0 phrase with a plaintext payload.
//
// MnemonicVersion 1 implies an era 0 phrase with an encrypted payload.
//
// Era numbers and MnemonicVersion numbers are a subtle distinction. Era numbers
// are internal to mnemonikey - they are never exported in the recovery phrase.
// MnemonicVersion numbers map (many-to-one) to Era numbers. More than one MnemonicVersion
// might use the same era. Recovery phrases whose versions share an era
// also share an identical procedure to derive keys after parsing, but the
// phrases themselves might be interpreted differently during recovery.
type MnemonicVersion uint

// Era returns the era number used by backups of this version.
//
// For version 0 and version 1 seeds, Era 0 is returned.
//
// Returns -1 for unknown versions.
func (version MnemonicVersion) Era() Era {
	switch version {
	case 0, 1:
		return 0
	}
	return -1
}

func (version MnemonicVersion) check() error {
	if version > MnemonicVersionLatest {
		return fmt.Errorf("%w: %d", ErrInvalidVersionNumber, version)
	}
	return nil
}

func (version MnemonicVersion) payloadBitCount() uint {
	switch version {
	case 0:
		return MnemonicVersionBitCount +
			CreationOffsetBitCount +
			ChecksumBitCount +
			EntropyBitCount

	case 1:
		return MnemonicVersionBitCount +
			CreationOffsetBitCount +
			ChecksumBitCount +
			EntropyBitCount +
			SaltBitCount +
			EncSeedVerifyBitCount
	}

	return 0
}

// MnemonicSize returns the number of mnemonic words needed to encode
// recovery phrases with this version.
func (version MnemonicVersion) MnemonicSize() int {
	return int(version.payloadBitCount() / mnemonic.BitsPerWord)
}

// Encrypted returns true if the version denotes a phrase which requires a password
// to decrypt it into a usable form.
func (version MnemonicVersion) Encrypted() bool {
	return version == 1
}
