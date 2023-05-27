package mnemonikey

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"

	"golang.org/x/crypto/argon2"

	"github.com/kklash/mnemonikey/mnemonic"
)

func encodeMnemonic(version MnemonicVersion, payloadBitBuffer *bitBuffer) ([]string, error) {
	// Compute & append checksum.
	checksum := checksumMask & crc32.ChecksumIEEE(payloadBitBuffer.Bytes())
	payloadBitBuffer.AppendTrailingBits(big.NewInt(int64(checksum)), ChecksumBitCount)

	expectedBitLen := version.payloadBitCount()
	actualBitLen := payloadBitBuffer.BitLen()
	if actualBitLen != expectedBitLen {
		return nil, fmt.Errorf(
			"payload has incorrect bit length, wanted %d for version %d, got %d bits",
			expectedBitLen, version, actualBitLen,
		)
	}

	indices, err := mnemonic.EncodeToIndices(payloadBitBuffer.Int(), payloadBitBuffer.BitLen())
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload to indices: %w", err)
	}

	words, err := mnemonic.EncodeToWords(indices)
	if err != nil {
		return nil, fmt.Errorf("failed to encode indices to words: %w", err)
	}
	return words, nil
}

// EncodeMnemonicPlaintext encodes the given seed and creationOffset into an English mnemonic
// recovery phrase. The recovery phrase alone is sufficient to recover the entire set of keys.
func EncodeMnemonicPlaintext(seed *Seed, creationOffset uint32) ([]string, error) {
	if err := seed.Era().check(); err != nil {
		return nil, err
	}

	// Version 0 indicates a plaintext phrase.
	version := MnemonicVersion(0)

	payloadBitBuffer := newBitBuffer(big.NewInt(int64(version)), MnemonicVersionBitCount)
	payloadBitBuffer.AppendTrailingBits(seed.Int(), EntropyBitCount)
	payloadBitBuffer.AppendTrailingBits(big.NewInt(int64(creationOffset)), CreationOffsetBitCount)

	return encodeMnemonic(version, payloadBitBuffer)
}

// EncodeMnemonicEncrypted encodes the given seed and creationOffset into an English
// mnemonic recovery phrase. The recovery phrase is encrypted with the given password
// so that the same password must be used upon recovery to decrypt the phrase.
//
// Without the password, someone in possession of an encrypted phrase would see the key's
// metadata (version, creation time) but would not be able to use it to derive the correct
// PGP private keys.
func EncodeMnemonicEncrypted(
	seed *Seed,
	creationOffset uint32,
	password []byte,
	random io.Reader,
) ([]string, error) {
	if err := seed.Era().check(); err != nil {
		return nil, err
	}

	if len(password) == 0 {
		return nil, errors.New("cannot encrypt recovery phrase with empty password")
	}

	// Version 1 indicates an encrypted phrase.
	version := MnemonicVersion(1)
	payloadBitBuffer := newBitBuffer(big.NewInt(int64(version)), MnemonicVersionBitCount)

	saltInt, err := rand.Int(random, big.NewInt(int64(1<<SaltBitCount)))
	if err != nil {
		return nil, err
	}

	encSeedSaltBuf := newBitBuffer(saltInt, SaltBitCount)
	encSeedSaltBuf.AppendTrailingBits(big.NewInt(int64(creationOffset)), CreationOffsetBitCount)

	encSeedKey := argon2.IDKey(password, encSeedSaltBuf.Bytes(), argonTimeFactor, argonMemoryFactor, argonThreads, 17)
	block, err := aes.NewCipher(encSeedKey[:16])
	if err != nil {
		return nil, err
	}
	encSeed := make([]byte, 16)
	block.Encrypt(encSeed, seed.Bytes())
	encSeedVerify := big.NewInt(int64(encSeedKey[16] & encSeedVerifyMask))

	// Append:
	// - encSeed
	// - salt
	// - encSeedVerify
	// - creationOffset
	payloadBitBuffer.AppendTrailingBits(new(big.Int).SetBytes(encSeed), EntropyBitCount)
	payloadBitBuffer.AppendTrailingBits(saltInt, SaltBitCount)
	payloadBitBuffer.AppendTrailingBits(encSeedVerify, EncSeedVerifyBitCount)
	payloadBitBuffer.AppendTrailingBits(big.NewInt(int64(creationOffset)), CreationOffsetBitCount)

	return encodeMnemonic(version, payloadBitBuffer)
}
