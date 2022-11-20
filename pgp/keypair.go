package pgp

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// KeyExpandInfo is the string used as the 'info' parameter to the
// HDKF-Expand function when generating a key pair.
const KeyExpandInfo = "mnemonikey"

// KeyPair represents a PGP signing and encryption key pair with an associated user identifier.
type KeyPair struct {
	UserID           *UserID
	MasterKey        *ED25519MasterKey
	EncryptionSubkey *Curve25519Subkey
}

// NewKeyPair derives a ED25519 and X25519 key pair by expanding the given seed
// using the HMAC-based Key Derivation Function (defined in RFC-5869) with SHA256.
//
// For safety, seed must be at least 16 bytes long to ensure security of the
// derived keys.
//
// Sets the key's creation and expiry times to the given values and binds
// the key to the given OpenPGP UserID.
func NewKeyPair(seed []byte, userID *UserID, creation, expiry time.Time) (*KeyPair, error) {
	if len(seed) < 16 {
		return nil, fmt.Errorf("seed of size %d is too small to be secure", len(seed))
	}
	keyReader := hkdf.Expand(sha256.New, seed, []byte(KeyExpandInfo))

	masterKeySeed := make([]byte, 32)
	if _, err := io.ReadFull(keyReader, masterKeySeed); err != nil {
		return nil, fmt.Errorf("failed to derive master key from seed: %w", err)
	}
	masterKey, err := NewED25519MasterKey(masterKeySeed, creation, expiry)
	if err != nil {
		return nil, err
	}

	subkeySeed := make([]byte, 32)
	if _, err := io.ReadFull(keyReader, subkeySeed); err != nil {
		return nil, fmt.Errorf("failed to derive encryption subkey from seed: %w", err)
	}
	encryptionSubkey, err := NewCurve25519Subkey(subkeySeed, creation, expiry, nil)
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
//
// If password is not nil and longer than 0 bytes, it is used as a key to
// encrypt the PGP private key packets using the S2K iterated & salted algorithm.
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
