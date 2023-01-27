package mnemonic

import (
	"errors"
	"math/big"
	"math/bits"
)

// BitsPerWord is the number of bits of information represented by each word
// in a mnemonic phrase.
const BitsPerWord uint = 12

var wordMask = big.NewInt(int64((1 << BitsPerWord) - 1))

// ErrInvalidIndex is returned when given a word index which
// cannot be represented in at most BitsPerWord bits.
var ErrInvalidIndex = errors.New("mnemonic index value is too large")

// EncodeToIndices encodes the given payload as a slice of word indices.
func EncodeToIndices(payloadInt *big.Int, bitSize uint) []uint16 {
	nWords := (bitSize + BitsPerWord - 1) / BitsPerWord
	indices := make([]uint16, nWords)
	for i := nWords - 1; payloadInt.BitLen() > 0; i-- {
		indices[i] = uint16(new(big.Int).And(payloadInt, wordMask).Uint64())
		payloadInt.Rsh(payloadInt, BitsPerWord)
	}
	return indices
}

// EncodeToMnemonic encodes the given word indices as a mnemonic phrase.
// The returned mnemonic is encoded with lower-case characters.
//
// Returns ErrInvalidIndex if any of the given indices are outside the
// domain of the word list.
func EncodeToMnemonic(indices []uint16) ([]string, error) {
	words := make([]string, len(indices))
	for i, index := range indices {
		if uint(bits.Len16(index)) > BitsPerWord {
			return nil, ErrInvalidIndex
		}
		words[i] = WordList[index]
	}
	return words, nil
}
