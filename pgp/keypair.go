package pgp

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// KeyPair represents a PGP signing and encryption key pair with an associated user identifier.
type KeyPair struct {
	UserID           *UserID
	MasterKey        *ED25519MasterKey
	EncryptionSubkey *Curve25519Subkey
}

func NewKeyPair(seed []byte, userID *UserID, birthday, expiry time.Time) (*KeyPair, error) {
	if len(seed) < 16 {
		return nil, fmt.Errorf("seed of size %d is too small to be secure", len(seed))
	}
	keyReader := hkdf.New(sha256.New, seed, nil, nil)

	masterKeySeed := make([]byte, 32)
	if _, err := io.ReadFull(keyReader, masterKeySeed); err != nil {
		return nil, fmt.Errorf("failed to derive master key from seed: %w", err)
	}
	masterKey, err := NewED25519MasterKey(masterKeySeed, birthday, expiry)
	if err != nil {
		return nil, err
	}

	subkeySeed := make([]byte, 32)
	if _, err := io.ReadFull(keyReader, subkeySeed); err != nil {
		return nil, fmt.Errorf("failed to derive encryption subkey from seed: %w", err)
	}
	encryptionSubkey, err := NewCurve25519Subkey(subkeySeed, birthday, expiry, nil)
	if err != nil {
		return nil, err
	}

	keyPair := &KeyPair{
		UserID:           userID,
		MasterKey:        masterKey,
		EncryptionSubkey: encryptionSubkey,
	}
	return keyPair, nil
}

// EncodePackets encodes the KeyPair as a series of binary OpenPGP packets.
func (keyPair *KeyPair) EncodePackets(password []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Master key
	masterPrivatePacket, err := keyPair.MasterKey.EncodePrivatePacket(password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode master key packet: %w", err)
	}
	buf.Write(masterPrivatePacket)

	// User ID
	buf.Write(keyPair.UserID.EncodePacket())

	// Self-certification signature for the master key
	buf.Write(keyPair.MasterKey.SelfCertify(keyPair.UserID).EncodePacket())

	// Encryption subkey
	encryptionSubkeyPacket, err := keyPair.EncryptionSubkey.EncodePrivatePacket(password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode encryption subkey packet: %w", err)
	}
	buf.Write(encryptionSubkeyPacket)

	// Subkey binding signature
	buf.Write(keyPair.MasterKey.BindSubkey(keyPair.EncryptionSubkey).EncodePacket())

	return buf.Bytes(), nil
}
