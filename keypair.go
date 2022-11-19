package mnemonikey

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/kklash/mnemonikey/mnemonic"
	"github.com/kklash/mnemonikey/pgp"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// EpochIncrement is the level of granularity available for the creation date of
// keys generated by mnemonikey. This limit is imposed to keep the size of the
// recovery phrase low, allowing more bits of data to be used to encode entropy.
const EpochIncrement = time.Hour * 24

// EpochStart is the start of the epoch after which key creation times are encoded
// in backup seeds as a day counter. It is exactly midnight in UTC time on the
// new year's eve between 2019 and 2020.
//
// In unix time, this epoch is exactly 1577836800 seconds after the unix epoch.
var EpochStart = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	// BirthdayBitCount is the number of bits used to represent a key creation date.
	BirthdayBitCount uint = 15

	// MinMnemonicSize is the minimum safe number of mnemonic words needed to encode
	// both the key birthday and at least 128 bits of seed entropy.
	MinMnemonicSize uint = 13
)

// MaxBirthday is the farthest point in the future that the mnemonikey recovery phrase
// encoding algorithm can represent key creation dates for.
var MaxBirthday = EpochStart.Add(EpochIncrement * (time.Duration(1<<BirthdayBitCount) - 1))

// ErrExpiryTooEarly is returned when constructing a DeterministicKeyPair, if its creation
// and expiry times are conflicting.
var ErrExpiryTooEarly = errors.New("expiry time predates key birthday")

// DeterministicKeyPair represents a determinstically generated PGP key pair. It contains
// a master certification+signing key, an encryption subkey, and the seed used to derive them.
type DeterministicKeyPair struct {
	pgpKeyPair      *pgp.KeyPair
	seed            *Seed
	keyCreationTime time.Time
	birthdayOffset  uint16
}

// NewDeterministicKeyPair constructs a DeterministicKeyPair from a seed.
//
// The key creation timestamp is hashed when computing the PGP public key fingerprint,
// and thus is critical to ensuring deterministic key re-generation. This function rounds
// the creation time down to the most recent EpochIncrement before creation, so that it can
// be encoded into a recovery mnemonic.
//
// The user ID parameters, name and email, are not required but are highly recommended
// to assist in identifying the key later.
func NewDeterministicKeyPair(
	seed *Seed,
	name string,
	email string,
	creation time.Time,
	expiry time.Time,
) (*DeterministicKeyPair, error) {
	userID := &pgp.UserID{
		Name:  name,
		Email: email,
	}

	birthdayOffset := creation.Sub(EpochStart) / EpochIncrement
	keyCreationTime := EpochStart.Add(EpochIncrement * birthdayOffset)

	if !expiry.IsZero() && keyCreationTime.After(expiry) {
		return nil, ErrExpiryTooEarly
	}

	pgpKeyPair, err := pgp.NewKeyPair(seed.Bytes(), userID, keyCreationTime, expiry)
	if err != nil {
		return nil, err
	}

	keyPair := &DeterministicKeyPair{
		pgpKeyPair:      pgpKeyPair,
		seed:            seed,
		keyCreationTime: keyCreationTime,
		birthdayOffset:  uint16(birthdayOffset),
	}

	return keyPair, nil
}

// CreatedAt returns the key creation date, rounded to an EpochIncrement
// after the EpochStart date.
func (keyPair *DeterministicKeyPair) CreatedAt() time.Time {
	return keyPair.keyCreationTime
}

// FingerprintV4 returns the SHA1 hash of the master key and the key user ID.
func (keyPair *DeterministicKeyPair) FingerprintV4() []byte {
	return keyPair.pgpKeyPair.MasterKey.FingerprintV4()
}

// EncodePGP encodes the key pair as a series of binary OpenPGP packets.
func (keyPair *DeterministicKeyPair) EncodePGP(password []byte) ([]byte, error) {
	return keyPair.pgpKeyPair.EncodePackets(password)
}

// EncodePGP encodes the key pair as a series of OpenPGP packets and formats
// them an ASCII armor block format.
func (keyPair *DeterministicKeyPair) EncodePGPArmor(password []byte) (string, error) {
	keyPacketData, err := keyPair.pgpKeyPair.EncodePackets(password)
	if err != nil {
		return "", err
	}
	pgpArmorKey, err := armorEncode(openpgp.PrivateKeyType, keyPacketData)
	if err != nil {
		return "", err
	}
	return pgpArmorKey, nil
}

// EncodeMnemonic encodes the key pair's seed and birthday into an English recovery mnemonic.
//
// The recovery mnemonic, plus the user ID (name and email) are sufficient to recover
// the entire key pair.
func (keyPair *DeterministicKeyPair) EncodeMnemonic() ([]string, error) {
	payloadInt := new(big.Int).Set(keyPair.seed.Value)
	payloadInt.Lsh(payloadInt, BirthdayBitCount)
	payloadInt.Or(payloadInt, big.NewInt(int64(keyPair.birthdayOffset)))

	indices := mnemonic.EncodeToIndices(payloadInt, keyPair.seed.EntropyBitCount+BirthdayBitCount)
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