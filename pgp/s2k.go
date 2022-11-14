package pgp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"math/big"
)

func stringToKey(hashFunc HashFuncID, password, salt []byte, byteCount int) []byte {
	preimage := append(salt, password...)

	h := hashFunc.New()
	m := byteCount / len(preimage)
	for i := 0; i < m; i++ {
		h.Write(preimage)
	}

	remainder := byteCount % len(preimage)
	h.Write(preimage[:remainder])
	return h.Sum(nil)
}

// https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#section-3.7.1.3-3
func s2kCountDecode(coded byte) int {
	return (16 + int(coded&0b1111)) << ((coded >> 4) + 6)
}

// EncryptS2K encrypts a given plaintext with the OpenPGP iterated & salted string-to-key
// algorithm. This is not a very secure symmetric cipher, as we only use a simple hash
// and not a dedicated PBKDF.
func EncryptS2K(hashFunc HashFuncID, plaintext, password []byte) ([]byte, error) {
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to read random salt: %w", err)
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to read random IV: %w", err)
	}

	secretKey := stringToKey(hashFunc, password, salt, s2kCountDecode(s2kCountMaximum))
	mpiPlaintext := EncodeMPI(new(big.Int).SetBytes(plaintext))

	checksum := sha1.Sum(mpiPlaintext)
	plaintextWithChecksum := append(mpiPlaintext, checksum[:]...)

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintextWithChecksum))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext, plaintextWithChecksum)

	buf := new(bytes.Buffer)
	buf.WriteByte(stringToKeySpecifierPrefix)

	switch hashFunc.New().Size() {
	case 128 / 8:
		buf.WriteByte(byte(CipherAlgoAES128))
	case 192 / 8:
		buf.WriteByte(byte(CipherAlgoAES192))
	case 256 / 8:
		buf.WriteByte(byte(CipherAlgoAES256))
	default:
		return nil, aes.KeySizeError(hashFunc.New().Size())
	}

	buf.WriteByte(stringToKeyUsageIteratedAndSalted)
	buf.WriteByte(byte(hashFunc))
	buf.Write(salt)
	buf.WriteByte(s2kCountMaximum)
	buf.Write(iv)
	buf.Write(ciphertext)
	return buf.Bytes(), nil
}
