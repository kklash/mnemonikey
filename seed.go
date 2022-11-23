package mnemonikey

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"github.com/kklash/mnemonikey/mnemonic"
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

// GenerateSeed generates a random Seed of a given bit size using the given random source.
func GenerateSeed(random io.Reader, wordCount uint) (*Seed, error) {
	entropyBitCount := wordCount*mnemonic.BitsPerWord - CreationOffsetBitCount

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

// Bytes returns the big-endian byte representation of seed.Value. Its length will be:
//
//	ceil(seed.EntropyBitCount / 8)
func (seed *Seed) Bytes() []byte {
	return seed.Value.FillBytes(make([]byte, (seed.EntropyBitCount+7)/8))
}
