package mnemonikey

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

var bigOne = big.NewInt(1)

// Seed represents a seed which was generated with a specific number of bits of entropy.
//
// Byte-representations of that seed should always be a fixed size, regardless of the
// actual integer value of the seed.
type Seed struct {
	Value *big.Int
}

func NewSeed(entropyInt *big.Int) *Seed {
	return &Seed{
		Value: entropyInt,
	}
}

// GenerateSeed generates a random Seed using the given random source.
func GenerateSeed(random io.Reader) (*Seed, error) {
	maxSeedInt := new(big.Int).Lsh(bigOne, EntropyBitCount)
	entropyInt, err := rand.Int(random, maxSeedInt)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate %d bits of secure random seed data: %w",
			EntropyBitCount, err,
		)
	}

	return NewSeed(entropyInt), nil
}

// Bytes returns the big-endian byte representation of seed.Value.
func (seed *Seed) Bytes() []byte {
	return seed.Value.FillBytes(make([]byte, (EntropyBitCount+7)/8))
}
