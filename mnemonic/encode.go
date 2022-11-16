package mnemonic

import (
	"errors"
	"math/big"
)

const BitsPerWord uint = 11

var wordMask = big.NewInt(int64((1 << BitsPerWord) - 1))

var ErrInvalidIndex = errors.New("mnemonic index value is too large")

func EncodeToIndices(payloadInt *big.Int, bitSize uint) ([]uint16, error) {
	nWords := (bitSize + BitsPerWord - 1) / BitsPerWord
	indices := make([]uint16, nWords)
	for i := nWords - 1; payloadInt.BitLen() > 0; i-- {
		indices[i] = uint16(new(big.Int).And(payloadInt, wordMask).Uint64())
		payloadInt.Rsh(payloadInt, BitsPerWord)
	}
	return indices, nil
}

func EncodeToMnemonic(indices []uint16) ([]string, error) {
	mnemonic := make([]string, len(indices))
	for i, index := range indices {
		if int(index) >= len(WordList) {
			return nil, ErrInvalidIndex
		}
		mnemonic[i] = WordList[index]
	}
	return mnemonic, nil
}
