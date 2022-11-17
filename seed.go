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
	Value           *big.Int
	EntropyBitCount uint
}

func NewSeed(entropyInt *big.Int, entropyBitCount uint) *Seed {
	return &Seed{
		Value:           entropyInt,
		EntropyBitCount: entropyBitCount,
	}
}

// RandomSeed generates a random Seed of a given bit size using the given random source.
func RandomSeed(random io.Reader, entropyBitCount uint) (*Seed, error) {
	maxSeedInt := new(big.Int).Lsh(bigOne, entropyBitCount)
	entropyInt, err := rand.Int(random, maxSeedInt)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate %d bits of secure random seed data: %w",
			entropyBitCount, err,
		)
	}

	return NewSeed(entropyInt, entropyBitCount), nil
}

func (seed *Seed) Bytes() []byte {
	return seed.Value.FillBytes(make([]byte, (seed.EntropyBitCount+7)/8))
}
