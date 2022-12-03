package pgp

import (
	"bytes"
	"fmt"
)

// KeySet represents a full set of PGP keys, with an associated user identifier.
type KeySet struct {
	// Required for a valid OpenPGP packet.
	UserID    *UserID
	MasterKey *ED25519MasterKey

	// Optional subkeys.
	EncryptionSubkey     *Curve25519Subkey
	AuthenticationSubkey *ED25519Subkey
	SigningSubkey        *ED25519Subkey
}

// EncodePackets encodes the KeySet as a series of binary OpenPGP packets.
//
// If password is not nil and longer than 0 bytes, it is used as a key to
// encrypt the PGP private key packets using the S2K iterated & salted algorithm.
func (keySet *KeySet) EncodePackets(password []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Master key
	masterPrivatePacket, err := keySet.MasterKey.EncodePrivatePacket(password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode master key packet: %w", err)
	}
	buf.Write(masterPrivatePacket)

	// User ID
	buf.Write(keySet.UserID.EncodePacket())

	var kdfParams *KeyDerivationParameters
	if keySet.EncryptionSubkey != nil {
		kdfParams = keySet.EncryptionSubkey.KDF
	}

	// Self-certification signature for the master key
	selfCertSig := keySet.MasterKey.SelfCertify(keySet.UserID, kdfParams)
	buf.Write(selfCertSig.EncodePacket())

	// Encryption subkey
	if keySet.EncryptionSubkey != nil {
		encryptionSubkeyPacket, err := keySet.EncryptionSubkey.EncodePrivatePacket(password)
		if err != nil {
			return nil, fmt.Errorf("failed to encode encryption subkey packet: %w", err)
		}
		buf.Write(encryptionSubkeyPacket)

		// Encryption subkey binding signature
		encSubkeyBindSig := keySet.MasterKey.BindSubkey(
			keySet.EncryptionSubkey.base,
			keyFlagEncryptCommunications|keyFlagEncryptStorage,
			keySet.EncryptionSubkey.Expiry,
		)
		buf.Write(encSubkeyBindSig.EncodePacket())
	}

	// Authentication subkey
	if keySet.AuthenticationSubkey != nil {
		authenticationSubkeyPacket, err := keySet.AuthenticationSubkey.EncodePrivatePacket(password)
		if err != nil {
			return nil, fmt.Errorf("failed to encode authentication subkey packet: %w", err)
		}
		buf.Write(authenticationSubkeyPacket)

		// Authentication subkey binding signature
		authSubkeyBindSig := keySet.MasterKey.BindSubkey(
			keySet.AuthenticationSubkey.base,
			keyFlagAuthenticate,
			keySet.AuthenticationSubkey.Expiry,
		)
		buf.Write(authSubkeyBindSig.EncodePacket())
	}

	// Signing subkey
	if keySet.SigningSubkey != nil {
		signingSubkeyPacket, err := keySet.SigningSubkey.EncodePrivatePacket(password)
		if err != nil {
			return nil, fmt.Errorf("failed to encode signing subkey packet: %w", err)
		}
		buf.Write(signingSubkeyPacket)

		// Signing subkey binding signature
		signSubkeyBindSig := keySet.MasterKey.BindSubkey(
			keySet.SigningSubkey.base,
			keyFlagSign,
			keySet.SigningSubkey.Expiry,
		)
		buf.Write(signSubkeyBindSig.EncodePacket())
	}

	return buf.Bytes(), nil
}
