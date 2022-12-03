package mnemonikey

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/kklash/mnemonikey/mnemonic"
	"github.com/kklash/mnemonikey/pgp"
)

// ErrExpiryTooEarly is returned when constructing a Mnemonikey, if its creation
// and expiry times are conflicting.
var ErrExpiryTooEarly = errors.New("expiry time predates key creation offset")

// ErrCreationTooLate is returned when constructing a Mnemonikey, if its creation
// time is too far in the future to fit in CreationOffsetBitCount.
var ErrCreationTooLate = errors.New("key creation time exceeds maximum")

// ErrCreationTooEarly is returned when constructing a Mnemonikey, if its creation
// time is before EpochStart.
var ErrCreationTooEarly = errors.New("key creation time exceeds maximum")

// Mnemonikey represents a determinstically generated set of PGP keys. It contains
// a master certification key, and encryption, authentication, and signing subkeys,
// as well as the seed data used to derive all four keys.
type Mnemonikey struct {
	pgpKeySet       *pgp.KeySet
	seed            *Seed
	keyCreationTime time.Time
}

// KeyOptions are a set of optional parameters which can be supplied when generating
// or recovering Mnemonikeys. They affect specific parameters in the output PGP keys
// but are not needed to recover the private keys themselves.
type KeyOptions struct {
	Name                      string
	Email                     string
	Expiry                    time.Time
}

// New constructs a Mnemonikey from a seed.
//
// The key creation timestamp is hashed when computing the PGP public key fingerprint,
// and thus is critical to ensuring deterministic key re-generation. This function rounds
// the creation time down to the most recent EpochIncrement before creation, so that it can
// be encoded into a recovery mnemonic.
//
// The user ID parameters, name and email, are not required but are highly recommended
// to assist in identifying the key later.
func New(seed *Seed, creation time.Time, opts *KeyOptions) (*Mnemonikey, error) {
	if opts == nil {
		opts = new(KeyOptions)
	}
	if !opts.Expiry.IsZero() && creation.After(opts.Expiry) {
		return nil, ErrExpiryTooEarly
	}
	if creation.After(MaxCreationTime) {
		return nil, ErrCreationTooLate
	} else if creation.Before(EpochStart) {
		return nil, ErrCreationTooEarly
	}

	// floor creation to next lowest EpochIncrement after EpochStart
	creationOffset := creation.Sub(EpochStart) / EpochIncrement
	creation = EpochStart.Add(EpochIncrement * creationOffset)

	pgpKeySet, err := derivePGPKeySet(seed.Bytes(), creation, opts)
	if err != nil {
		return nil, err
	}

	mnk := &Mnemonikey{
		seed:            seed,
		keyCreationTime: creation,
		pgpKeySet:       pgpKeySet,
	}

	return mnk, nil
}

// CreatedAt returns the key creation date, rounded to an EpochIncrement
// after the EpochStart date.
func (mnk *Mnemonikey) CreatedAt() time.Time {
	return mnk.keyCreationTime
}

// FingerprintV4 returns the SHA1 hash of the master key and the key user ID.
func (mnk *Mnemonikey) FingerprintV4() []byte {
	return mnk.pgpKeySet.MasterKey.FingerprintV4()
}

// EncodePGP encodes the Mnemonikey as a series of binary OpenPGP packets.
func (mnk *Mnemonikey) EncodePGP(password []byte) ([]byte, error) {
	return mnk.pgpKeySet.EncodePackets(password)
}

// EncodePGP encodes the Mnemonikey as a series of OpenPGP packets and formats
// them an ASCII armor block format.
func (mnk *Mnemonikey) EncodePGPArmor(password []byte) (string, error) {
	keyPacketData, err := mnk.pgpKeySet.EncodePackets(password)
	if err != nil {
		return "", err
	}
	pgpArmorKey, err := armorEncode(openpgp.PrivateKeyType, keyPacketData)
	if err != nil {
		return "", err
	}
	return pgpArmorKey, nil
}

// EncodeMnemonic encodes the Mnemonikey seed and creation offset into an English recovery
// mnemonic. The recovery mnemonic alone is sufficient to recover the entire set of keys.
func (mnk *Mnemonikey) EncodeMnemonic() ([]string, error) {
	creationOffset := int64(mnk.keyCreationTime.Sub(EpochStart) / EpochIncrement)

	payloadInt := new(big.Int).Set(mnk.seed.Value)
	payloadInt.Lsh(payloadInt, CreationOffsetBitCount)
	payloadInt.Or(payloadInt, big.NewInt(creationOffset))

	payloadBitCount := EntropyBitCount + CreationOffsetBitCount
	payloadBytes := payloadInt.FillBytes(make([]byte, (payloadBitCount+7)/8))

	checksum := checksumMask & crc32.ChecksumIEEE(payloadBytes)
	payloadInt.Lsh(payloadInt, ChecksumBitCount)
	payloadInt.Or(payloadInt, big.NewInt(int64(checksum)))

	indices := mnemonic.EncodeToIndices(payloadInt, payloadBitCount+ChecksumBitCount)
	words, err := mnemonic.EncodeToMnemonic(indices)
	if err != nil {
		return nil, fmt.Errorf("failed to encode indices to words: %w", err)
	}
	return words, nil
}

func armorEncode(blockType string, data []byte) (string, error) {
	buf := new(bytes.Buffer)
	armorWriter, err := armor.Encode(buf, blockType, nil)
	if err != nil {
		return "", fmt.Errorf("failed to construct armor encoder: %w", err)
	}
	if _, err := armorWriter.Write(data); err != nil {
		return "", fmt.Errorf("failed to write PGP packets to armor encoder: %w", err)
	}
	if err := armorWriter.Close(); err != nil {
		return "", fmt.Errorf("failed to close PGP armor encoder: %w", err)
	}
	return buf.String(), nil
}
