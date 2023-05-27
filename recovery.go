package mnemonikey

import (
	"crypto/aes"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"strings"
	"time"

	"github.com/kklash/mnemonikey/mnemonic"
	"github.com/kklash/wordlist4096"
	"golang.org/x/crypto/argon2"
)

// ErrInvalidChecksum is returned when decoding a mnemonic fails due
// to a checksum mismatch.
var ErrInvalidChecksum = errors.New("failed to validate checksum embedded in mnemonic phrase")

// ErrInvalidWordCount is returned when decoding a mnemonic recovery
// phrase whose word count is not the correct size.
var ErrInvalidWordCount = errors.New("mnemonic is not the correct length")

// ErrMnemonicDecryption is returned when decoding an encrypted mnemonic recovery phrase fails,
// usually due to a bad password.
var ErrMnemonicDecryption = errors.New("failed to decrypt entropy")

// DecodedMnemonic represents a mnemonic recovery phrase immediately after mnemonic decoding.
//
// A DecodedMnemonic may contain plaintext entropy or encrypted entropy. If the entropy data
// is encrypted, the caller will need to decrypt it with the DecryptSeed method, providing
// the correct password.
type DecodedMnemonic struct {
	// Version is the version number of the decoded mnemonic. This version number tells mnemonikey
	// how to interpret the data embedded in the mnemonic recovery phrase.
	Version MnemonicVersion

	entropy        *big.Int
	salt           *big.Int
	encSeedVerify  byte
	creationOffset uint32
}

// Encrypted indicates whether the mnemonic recovery phrase is encrypted or not.
//
// Encrypted phrases must be decrypted with the DecryptSeed method to reveal their
// authentic seed data.
func (dm *DecodedMnemonic) Encrypted() bool {
	return dm.Version.Encrypted()
}

// Creation returns the creation time of the PGP keys this mnemonic phrase will derive.
func (dm *DecodedMnemonic) Creation() time.Time {
	return EpochStart.Add(time.Duration(dm.creationOffset) * EpochIncrement)
}

// CreationOffset returns the raw creation offset value encoded in the mnemonic phrase.
func (dm *DecodedMnemonic) CreationOffset() uint32 {
	return dm.creationOffset
}

// DecryptSeed decrypts the encrypted entropy in the mnemonic using the
// given password. Returns ErrMnemonicDecryption if the password was
// incorrect.
//
// If DecryptSeed returns successfully, this does not guarantee that the
// correct password was provided. Five checksum bits are used to validate
// whether the correct password was used for decryption. Because this checksum
// is very small, there is a 1 in 32 chance of an incorrect password colliding
// with this checksum and returning a false-success. Contrastingly, correct passwords
// always decrypt the entropy successfully.
//
// If the DecodedMnemonic is not encrypted, this method returns the same
// result as calling the Seed method.
func (dm *DecodedMnemonic) DecryptSeed(password []byte) (*Seed, error) {
	// Mnemonic is not encrypted, just return the plaintext seed.
	if !dm.Encrypted() {
		return dm.Seed()
	}

	encSeedSaltBuf := newBitBuffer(dm.salt, SaltBitCount)
	encSeedSaltBuf.AppendTrailingBits(big.NewInt(int64(dm.creationOffset)), CreationOffsetBitCount)

	encSeedKey := argon2.IDKey(
		password,
		encSeedSaltBuf.Bytes(),
		argonTimeFactor,
		argonMemoryFactor,
		argonThreads,
		17,
	)

	encSeedVerifyActual := encSeedKey[16] & encSeedVerifyMask
	if encSeedVerifyActual != dm.encSeedVerify {
		return nil, fmt.Errorf("%w: incorrect password", ErrMnemonicDecryption)
	}

	block, err := aes.NewCipher(encSeedKey[:16])
	if err != nil {
		return nil, err
	}

	encSeed := dm.entropy.FillBytes(make([]byte, 16))
	decSeed := make([]byte, 16)

	block.Decrypt(decSeed, encSeed)
	entropyInt := new(big.Int).SetBytes(decSeed)
	return NewSeed(dm.Version.Era(), entropyInt)
}

// Seed returns the embedded Seed, used to re-derive PGP keys.
//
// Returns ErrMnemonicDecryption if the entropy data in the mnemonic recovery phrase
// is encrypted.
func (dm *DecodedMnemonic) Seed() (*Seed, error) {
	if dm.Encrypted() {
		return nil, fmt.Errorf("%w: must decrypt entropy", ErrMnemonicDecryption)
	}
	return NewSeed(dm.Version.Era(), dm.entropy)
}

// RecoverPlaintext decodes a seed and creation offset from the given recovery mnemonic and
// re-derives its child PGP keys.
//
// If the original key's user ID is not a standard RFC-2822 mail name-addr format (NAME <EMAIL>),
// then simply provide the entire user ID as the name parameter, and leave the email parameter
// empty.
func RecoverPlaintext(words []string, keyOpts *KeyOptions) (*Mnemonikey, error) {
	decodedMnemonic, err := DecodeMnemonic(words)
	if err != nil {
		return nil, err
	}

	seed, err := decodedMnemonic.Seed()
	if err != nil {
		return nil, err
	}

	mnk, err := New(seed, decodedMnemonic.Creation(), keyOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to recover key from decoded mnemonic: %w", err)
	}

	return mnk, nil
}

// RecoverEncrypted decodes the given recovery mnemonic, and decrypts the embedded
// entropy using the given password, and re-derives child PGP keys.
//
// If RecoverEncrypted returns successfully, this does not guarantee that the
// correct password was provided. Five checksum bits in the mnemonic are used to
// validate whether the correct password was used for decryption. Because this checksum
// is very small, there is a 1 in 32 chance of an incorrect password colliding
// with this checksum and returning a false-success. Contrastingly, correct passwords
// always decrypt the entropy successfully.
//
// If the original key's user ID is not a standard RFC-2822 mail name-addr format (NAME <EMAIL>),
// then simply provide the entire user ID as the name parameter, and leave the email parameter
// empty.
func RecoverEncrypted(words []string, password []byte, keyOpts *KeyOptions) (*Mnemonikey, error) {
	decodedMnemonic, err := DecodeMnemonic(words)
	if err != nil {
		return nil, err
	}

	seed, err := decodedMnemonic.DecryptSeed(password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt seed during recovery: %w", err)
	}

	mnk, err := New(seed, decodedMnemonic.Creation(), keyOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to recover key from decrypted mnemonic: %w", err)
	}

	return mnk, nil
}

// DecodeMnemonic decodes a mnemonic recovery phrase into a decoded data structure.
//
// Note the decoded mnemonic might contain encrypted entropy, which will require decryption
// before proceeding further with the recovery process.
func DecodeMnemonic(words []string) (*DecodedMnemonic, error) {
	if len(words) == 0 {
		return nil, ErrInvalidWordCount
	}

	version, err := ParseMnemonicVersion(words[0])
	if err != nil {
		return nil, err
	}

	if err := version.check(); err != nil {
		return nil, err
	}

	if len(words) != version.MnemonicSize() {
		return nil, ErrInvalidWordCount
	}

	indices, err := mnemonic.DecodeWords(words)
	if err != nil {
		return nil, err
	}

	payloadInt, err := mnemonic.DecodeIndices(indices)
	if err != nil {
		return nil, err
	}

	payloadBitBuffer := newBitBuffer(payloadInt, uint(len(words))*mnemonic.BitsPerWord)

	// Extract checksum for the seed
	expectedChecksum := uint32(payloadBitBuffer.PopTrailingBits(ChecksumBitCount).Uint64())

	// Confirm checksum is correct.
	checksum := checksumMask & crc32.ChecksumIEEE(payloadBitBuffer.Bytes())
	if checksum != expectedChecksum {
		return nil, ErrInvalidChecksum
	}

	// We already read the version number, so just discard the leading version bits.
	_ = payloadBitBuffer.PopLeadingBits(MnemonicVersionBitCount)

	entropy := payloadBitBuffer.PopLeadingBits(EntropyBitCount)
	decodedMnemonic := &DecodedMnemonic{
		Version: version,
		entropy: entropy,
	}

	// Decode fields only found in encrypted phrases.
	if version == 1 {
		decodedMnemonic.salt = payloadBitBuffer.PopLeadingBits(SaltBitCount)
		decodedMnemonic.encSeedVerify = byte(payloadBitBuffer.PopLeadingBits(EncSeedVerifyBitCount).Uint64())
	}

	decodedMnemonic.creationOffset = uint32(payloadBitBuffer.PopLeadingBits(CreationOffsetBitCount).Uint64())

	if payloadBitBuffer.BitLen() != 0 {
		return nil, fmt.Errorf("unexpected extra %d bits left after decoding", payloadBitBuffer.BitLen())
	}

	return decodedMnemonic, nil
}

// ParseMnemonicVersion parses the version number encoded in first word of the recovery phrase. Returns
// mnemonic.ErrInvalidWord if the word is not in the word list. Returns ErrUnsupportedSeedVersion
// if the version number is greater than MnemonicVersionLatest.
//
// This can be used to inform a user ahead of time if the user's mnemonic recovery phrase is
// not supported by this version of the Mnemonikey library, thus saving them from entering
// the whole phrase in needlessly.
//
// The returned MnemonicVersion can be used to dynamically determine how many words long the
// whole recovery phrase should be, and to determine if the phrase is encrypted or not.
func ParseMnemonicVersion(firstWord string) (version MnemonicVersion, err error) {
	index, ok := wordlist4096.WordMap[strings.ToLower(firstWord)]
	if !ok {
		return 0, mnemonic.ErrInvalidWord
	}

	version = MnemonicVersion(uint(index) >> (wordlist4096.BitsPerWord - MnemonicVersionBitCount))
	err = version.check()
	return
}
