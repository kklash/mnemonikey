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

const EpochIncrement = time.Hour * 24

// EpochStart is the start of the epoch after which key creation times are encoded
// in backup seeds as a day counter. It is exactly midnight in UTC time on the
// new year's eve between 2019 and 2020.
//
// In unix time, this epoch is exactly 1577836800 seconds after the unix epoch.
var EpochStart = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	BirthdayBitCount uint = 15
	MinMnemonicSize  uint = 13
)

var MaxBirthday = EpochStart.Add(EpochIncrement * (time.Duration(1<<BirthdayBitCount) - 1))

var ErrExpiryTooEarly = errors.New("expiry time predates key birthday")

type DeterministicKeyPair struct {
	pgpKeyPair     *pgp.KeyPair
	seed           *Seed
	birthdayOffset uint16
}

func NewDeterministicKeyPair(seed *Seed, name, email string, now, expiry time.Time) (*DeterministicKeyPair, error) {
	userID := &pgp.UserID{
		Name:  name,
		Email: email,
	}

	birthdayOffset := now.Sub(EpochStart) / EpochIncrement
	keyCreationTime := EpochStart.Add(EpochIncrement * birthdayOffset)

	if !expiry.IsZero() && keyCreationTime.After(expiry) {
		return nil, ErrExpiryTooEarly
	}

	pgpKeyPair, err := pgp.NewKeyPair(seed.Bytes(), userID, keyCreationTime, expiry)
	if err != nil {
		return nil, err
	}

	keyPair := &DeterministicKeyPair{
		pgpKeyPair:     pgpKeyPair,
		seed:           seed,
		birthdayOffset: uint16(birthdayOffset),
	}

	return keyPair, nil
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

	indices, err := mnemonic.EncodeToIndices(payloadInt, keyPair.seed.EntropyBitCount+BirthdayBitCount)
	if err != nil {
		return nil, fmt.Errorf("failed to encode seed to indices: %w", err)
	}

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
