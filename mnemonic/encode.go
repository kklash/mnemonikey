package mnemonic

import (
	"errors"
	"math/big"
)

var elevenMask = big.NewInt(0b11111111111)

var ErrInvalidIndex = errors.New("mnemonic index value is too large")

func EncodeToIndices(payloadInt *big.Int, bitSize int) ([]uint16, error) {
	nWords := (bitSize + 10) / 11
	indices := make([]uint16, nWords)
	for i := nWords - 1; payloadInt.BitLen() > 0; i-- {
		indices[i] = uint16(new(big.Int).And(payloadInt, elevenMask).Uint64())
		payloadInt.Rsh(payloadInt, 11)
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
