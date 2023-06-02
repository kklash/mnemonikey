package mnemonikey

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

var bigOne = big.NewInt(1)

// Seed represents a seed which was generated with a specific number of bits of entropy.
// Each Seed contains an era number which indicates how the seed should be used to
// derive PGP keys.
//
// Byte-representations of that seed should always be a fixed size, regardless of the
// actual integer value of the seed.
type Seed struct {
	era   Era
	value *big.Int
}

// NewSeed constructs a Seed with a given era number using the provided entropy integer.
//
// Returns ErrUnsupportedSeedEra if the era number is greater than EraLatest.
//
// Returns an error if entropyInt's bit-length is greater than EntropyBitCount.
func NewSeed(era Era, entropyInt *big.Int) (*Seed, error) {
	if err := era.check(); err != nil {
		return nil, err
	}

	if l := entropyInt.BitLen(); l > EntropyBitCount {
		return nil, fmt.Errorf(
			"provided entropy integer is %d bits, exceeding maximum size of %d",
			l, EntropyBitCount,
		)
	}

	seed := &Seed{
		era:   era,
		value: entropyInt,
	}

	return seed, nil
}

// Era returns the era number of the seed, used for determining how keys are derived.
func (seed *Seed) Era() Era {
	return seed.era
}

// Int returns a copy of the seed entropy value as an integer.
func (seed *Seed) Int() *big.Int {
	return new(big.Int).Set(seed.value)
}

// Bytes returns the big-endian byte representation of seed.Int().
func (seed *Seed) Bytes() []byte {
	return seed.value.FillBytes(make([]byte, (EntropyBitCount+7)/8))
}

// GenerateSeed generates a random Seed using the given random source.
//
// The generated seed will use EraLatest.
func GenerateSeed(random io.Reader) (*Seed, error) {
	maxSeedInt := new(big.Int).Lsh(bigOne, EntropyBitCount)
	entropyInt, err := rand.Int(random, maxSeedInt)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate %d bits of secure random seed data: %w",
			EntropyBitCount, err,
		)
	}

	return NewSeed(EraLatest, entropyInt)
}
