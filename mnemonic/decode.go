package mnemonic

import (
	"errors"
	"math/big"
)

var ErrInvalidWord = errors.New("word is not a member of the BIP39 word list")

func DecodeIndices(indices []uint16) ([]byte, error) {
	payloadInt := new(big.Int)
	payloadSize := (len(indices)*11 + 7) / 8

	for _, index := range indices {
		if int(index) >= len(WordList) {
			return nil, ErrInvalidIndex
		}
		payloadInt.Lsh(payloadInt, 11)
		payloadInt.Or(payloadInt, big.NewInt(int64(index)))
	}

	return payloadInt.FillBytes(make([]byte, payloadSize)), nil
}

func DecodeMnemonic(mnemonic []string) ([]uint16, error) {
	indices := make([]uint16, len(mnemonic))
	for i, word := range mnemonic {
		index, ok := WordMap[word]
		if !ok {
			return nil, ErrInvalidWord
		}
		indices[i] = index
	}
	return indices, nil
}
