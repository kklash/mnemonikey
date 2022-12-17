package mnemonikey

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var bigOne = big.NewInt(1)

// ErrUnsupportedSeedVersion is returned when an unknown or outdated version
// number was used - For example, this can occur when recovering or decoding
// a mnemonikey backup phrase exported by a newer version of mnemonikey.
var ErrUnsupportedSeedVersion = errors.New("unsupported seed version number")

// Seed represents a seed which was generated with a specific number of bits of entropy.
// Each Seed contains a version number which indicates how the seed should be used to
// derive PGP keys.
//
// Byte-representations of that seed should always be a fixed size, regardless of the
// actual integer value of the seed.
type Seed struct {
	Version uint
	Value   *big.Int
}

// NewSeed constructs a Seed at a given version number using the provided entropy integer.
//
// Returns ErrUnsupportedSeedVersion if the version number is greater than VersionLatest.
func NewSeed(version uint, entropyInt *big.Int) (*Seed, error) {
	if err := checkSeedVersion(version); err != nil {
		return nil, err
	}
	seed := &Seed{
		Version: version,
		Value:   entropyInt,
	}
	return seed, nil
}

// GenerateSeed generates a random Seed using the given random source.
//
// The generated seed will use VersionLatest.
func GenerateSeed(random io.Reader) (*Seed, error) {
	maxSeedInt := new(big.Int).Lsh(bigOne, EntropyBitCount)
	entropyInt, err := rand.Int(random, maxSeedInt)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate %d bits of secure random seed data: %w",
			EntropyBitCount, err,
		)
	}

	return NewSeed(VersionLatest, entropyInt)
}

// Bytes returns the big-endian byte representation of seed.Value.
func (seed *Seed) Bytes() []byte {
	return seed.Value.FillBytes(make([]byte, (EntropyBitCount+7)/8))
}

func checkSeedVersion(version uint) error {
	if version > VersionLatest {
		return fmt.Errorf("%w: %d", ErrUnsupportedSeedVersion, version)
	}
	return nil
}
