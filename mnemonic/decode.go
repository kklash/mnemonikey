package mnemonic

import (
	"errors"
	"math/big"
	"math/bits"
	"strings"
)

// ErrInvalidWord is returned when a word is passed to DecodeMnemonic which is not
// a member of the BIP39 english word list.
var ErrInvalidWord = errors.New("word is not a member of the BIP39 word list")

// DecodeIndices decodes the given BIP39 indices into an integer representation.
//
// Returns ErrInvalidIndex if any of the given indices are outside the
// domain of the word list size.
func DecodeIndices(indices []uint16) (*big.Int, error) {
	payloadInt := new(big.Int)

	for _, index := range indices {
		if uint(bits.Len16(index)) > BitsPerWord {
			return nil, ErrInvalidIndex
		}
		payloadInt.Lsh(payloadInt, BitsPerWord)
		payloadInt.Or(payloadInt, big.NewInt(int64(index)))
	}

	return payloadInt, nil
}

// DecodeMnemonic decodes the given mnemonic phrase into their indices in the
// BIP39 english word list. The words can be in either upper or lower case.
//
// Returns ErrInvalidWord if any of the words are not members of the BIP39
// english word list.
func DecodeMnemonic(words []string) ([]uint16, error) {
	indices := make([]uint16, len(words))
	for i, word := range words {
		index, ok := WordMap[strings.ToLower(word)]
		if !ok {
			return nil, ErrInvalidWord
		}
		indices[i] = index
	}
	return indices, nil
}
