package mnemonic

import (
	"errors"
	"fmt"
	"math/big"
	"math/bits"

	"github.com/kklash/wordlist4096"
)

// BitsPerWord is the number of bits of information represented by each word
// in the wordlist.
const BitsPerWord = wordlist4096.BitsPerWord

var wordMask = big.NewInt(int64((1 << BitsPerWord) - 1))

// ErrInvalidIndex is returned when given a word index which
// cannot be represented in at most BitsPerWord bits.
var ErrInvalidIndex = errors.New("word index value is too large")

// EncodeToIndices encodes the given payload as a slice of word indices.
//
// The bitSize parameter determines how many words will be used to encode the
// payload, which is calculated as:
//
//	nWords = ceil(bitSize / BitsPerWord)
//
// bitSize does not necessarily have to be evenly divisible by BitsPerWord. If there is
// any unused space, it will be encoded at the leading edge of the resulting slice of indices.
func EncodeToIndices(payloadInt *big.Int, bitSize uint) ([]uint16, error) {
	if payloadLen := payloadInt.BitLen(); uint(payloadLen) > bitSize {
		return nil, fmt.Errorf("payload size (%d bits) is larger than given bitSize %d", payloadLen, bitSize)
	}

	nWords := (bitSize + BitsPerWord - 1) / BitsPerWord
	indices := make([]uint16, nWords)
	for i := nWords - 1; payloadInt.BitLen() > 0; i-- {
		indices[i] = uint16(new(big.Int).And(payloadInt, wordMask).Uint64())
		payloadInt.Rsh(payloadInt, BitsPerWord)
	}
	return indices, nil
}

// EncodeToWords encodes the given word indices as a series of words from
// the wordlist. The returned phrase is encoded with lower-case characters.
//
// Returns ErrInvalidIndex if any of the given indices are outside the
// domain of the word list.
func EncodeToWords(indices []uint16) ([]string, error) {
	words := make([]string, len(indices))
	for i, index := range indices {
		if uint(bits.Len16(index)) > BitsPerWord {
			return nil, ErrInvalidIndex
		}
		words[i] = wordlist4096.WordList[index]
	}
	return words, nil
}
