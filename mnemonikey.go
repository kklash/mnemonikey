package mnemonikey

import (
	"fmt"
	"math/big"
	"time"

	"github.com/kklash/mnemonikey/mnemonic"
	"github.com/kklash/mnemonikey/pgp"
)

const EpochIncrement = time.Hour * 24

// EpochStart is the start of the epoch after which key creation times are encoded
// in backup seeds as a day counter.
//
// In unix time, this epoch is exactly 1577836800 seconds after the unix epoch.
var EpochStart = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

const maxBirthdayBits = 15

var MaxBirthday = EpochStart.Add(EpochIncrement * (time.Duration(1<<maxBirthdayBits) - 1))

type DeterministicKeyPair struct {
	pgpKeyPair *pgp.KeyPair
	seed       []byte
	birthday   uint16
}

func NewDeterministicKeyPair(seed []byte, name, email string, now, expiry time.Time) (*DeterministicKeyPair, error) {
	userID := &pgp.UserID{
		Name:  name,
		Email: email,
	}

	birthdayOffset := now.Sub(EpochStart) / EpochIncrement

	keyCreationTime := EpochStart.Add(EpochIncrement * birthdayOffset)
	pgpKeyPair, err := pgp.NewKeyPair(seed, userID, keyCreationTime, expiry)
	if err != nil {
		return nil, err
	}

	keyPair := &DeterministicKeyPair{
		pgpKeyPair: pgpKeyPair,
		seed:       seed,
		birthday:   uint16(birthdayOffset),
	}

	return keyPair, nil
}

func (keyPair *DeterministicKeyPair) EncodePGP(password []byte) ([]byte, error) {
	return keyPair.pgpKeyPair.EncodePackets(password)
}

func (keyPair *DeterministicKeyPair) EncodeMnemonic() ([]string, error) {
	payloadInt := new(big.Int).SetBytes(keyPair.seed)
	payloadInt.Lsh(payloadInt, uint(maxBirthdayBits))
	payloadInt.Or(payloadInt, big.NewInt(int64(keyPair.birthday)))

	indices, err := mnemonic.EncodeToIndices(payloadInt, len(keyPair.seed)*8+maxBirthdayBits)
	if err != nil {
		return nil, fmt.Errorf("failed to encode seed to indices: %w", err)
	}

	words, err := mnemonic.EncodeToMnemonic(indices)
	if err != nil {
		return nil, fmt.Errorf("failed to encode indices to words: %w", err)
	}
	return words, nil
}

func DecodeMnemonic(words []string) (seed []byte, birthday time.Time, err error) {
	indices, err := mnemonic.DecodeMnemonic(words)
	if err != nil {
		return
	}

	payloadInt, err := mnemonic.DecodeIndices(indices)
	if err != nil {
		return
	}

	// Determine key birthday from lowest trailing 15 bits
	birthdayOffset := new(big.Int).And(payloadInt, big.NewInt(int64((1<<maxBirthdayBits)-1))).Int64()
	birthday = EpochStart.Add(time.Duration(birthdayOffset) * EpochIncrement)
	payloadInt.Rsh(payloadInt, maxBirthdayBits)

	// Remaining bits are all seed data
	seed = payloadInt.FillBytes(make([]byte, 16))

	return
}
