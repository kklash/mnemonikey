package pgp

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	// KeyExpandInfoMaster is the string used as the 'info' parameter to the
	// HDKF-Expand function when generating a master key from a seed.
	KeyExpandInfoMaster = "mnemonikey master key"

	// KeyExpandInfoEncryption is the string used as the 'info' parameter to the
	// HDKF-Expand function when generating an encryption subkey from a seed.
	KeyExpandInfoEncryption = "mnemonikey encryption subkey"

	// KeyExpandInfoAuthentication is the string used as the 'info' parameter to the
	// HDKF-Expand function when generating an authentication subkey from a seed.
	KeyExpandInfoAuthentication = "mnemonikey authentication subkey"

	// KeyExpandInfoSigning is the string used as the 'info' parameter to the
	// HDKF-Expand function when generating a signing subkey from a seed.
	KeyExpandInfoSigning = "mnemonikey signing subkey"
)

func hkdfExpand32(seed []byte, info string) ([]byte, error) {
	keyOutput := make([]byte, 32)
	keyReader := hkdf.Expand(sha256.New, seed, []byte(info))
	if _, err := io.ReadFull(keyReader, keyOutput); err != nil {
		return nil, err
	}
	return keyOutput, nil
}

// KeyPair represents a PGP signing and encryption key pair with an associated user identifier.
type KeyPair struct {
	UserID               *UserID
	MasterKey            *ED25519MasterKey
	EncryptionSubkey     *Curve25519Subkey
	AuthenticationSubkey *ED25519Subkey
	SigningSubkey        *ED25519Subkey
}

// NewKeyPair derives a KeyPair by expanding the given seed using the
// HMAC-based Key Derivation Function (defined in RFC-5869) with SHA256.
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

	masterKeySeed, err := hkdfExpand32(seed, KeyExpandInfoMaster)
	if err != nil {
		return nil, fmt.Errorf("failed to derive master key from seed: %w", err)
	}
	masterKey, err := NewED25519MasterKey(masterKeySeed, creation, expiry)
	if err != nil {
		return nil, err
	}

	encryptionSubkeySeed, err := hkdfExpand32(seed, KeyExpandInfoEncryption)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption subkey from seed: %w", err)
	}
	encryptionSubkey, err := NewCurve25519Subkey(encryptionSubkeySeed, creation, expiry, nil)
	if err != nil {
		return nil, err
	}

	authenticationSubkeySeed, err := hkdfExpand32(seed, KeyExpandInfoAuthentication)
	if err != nil {
		return nil, fmt.Errorf("failed to derive authentication subkey from seed: %w", err)
	}
	authenticationSubkey, err := NewED25519Subkey(authenticationSubkeySeed, creation, expiry)
	if err != nil {
		return nil, err
	}

	signingSubkeySeed, err := hkdfExpand32(seed, KeyExpandInfoSigning)
	if err != nil {
		return nil, fmt.Errorf("failed to derive signing subkey from seed: %w", err)
	}
	signingSubkey, err := NewED25519Subkey(signingSubkeySeed, creation, expiry)
	if err != nil {
		return nil, err
	}

	keyPair := &KeyPair{
		UserID:               userID,
		MasterKey:            masterKey,
		EncryptionSubkey:     encryptionSubkey,
		AuthenticationSubkey: authenticationSubkey,
		SigningSubkey:        signingSubkey,
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
	selfCertSig := keyPair.MasterKey.SelfCertify(keyPair.UserID, keyPair.EncryptionSubkey.KDF)
	buf.Write(selfCertSig.EncodePacket())

	// Encryption subkey
	encryptionSubkeyPacket, err := keyPair.EncryptionSubkey.EncodePrivatePacket(password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode encryption subkey packet: %w", err)
	}
	buf.Write(encryptionSubkeyPacket)

	// Encryption subkey binding signature
	encSubkeyBindSig := keyPair.MasterKey.BindSubkey(
		keyPair.EncryptionSubkey.base,
		keyFlagEncryptCommunications|keyFlagEncryptStorage,
		keyPair.EncryptionSubkey.Expiry,
	)
	buf.Write(encSubkeyBindSig.EncodePacket())

	// Authentication subkey
	authenticationSubkeyPacket, err := keyPair.AuthenticationSubkey.EncodePrivatePacket(password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode authentication subkey packet: %w", err)
	}
	buf.Write(authenticationSubkeyPacket)

	// Authentication subkey binding signature
	authSubkeyBindSig := keyPair.MasterKey.BindSubkey(
		keyPair.AuthenticationSubkey.base,
		keyFlagAuthenticate,
		keyPair.AuthenticationSubkey.Expiry,
	)
	buf.Write(authSubkeyBindSig.EncodePacket())

	// Signing subkey
	signingSubkeyPacket, err := keyPair.SigningSubkey.EncodePrivatePacket(password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signing subkey packet: %w", err)
	}
	buf.Write(signingSubkeyPacket)

	// Signing subkey binding signature
	signSubkeyBindSig := keyPair.MasterKey.BindSubkey(
		keyPair.SigningSubkey.base,
		keyFlagSign,
		keyPair.SigningSubkey.Expiry,
	)
	buf.Write(signSubkeyBindSig.EncodePacket())

	return buf.Bytes(), nil
}
