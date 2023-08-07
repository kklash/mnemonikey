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

// encodeEncryptionSubkeyPackets encodes the encryption subkey of the KeySet and its
// binding signature as a series of binary OpenPGP packets. Requires the MasterKey
// field to be defined, for creating the binding signature.
//
// If password is not nil and longer than 0 bytes, it is used as a key to
// encrypt the PGP private key packet using the S2K iterated & salted algorithm.
func (keySet *KeySet) encodeEncryptionSubkeyPackets(password []byte) ([]byte, error) {
	encryptionSubkeyPacket, err := keySet.EncryptionSubkey.EncodePrivatePacket(password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode encryption subkey packet: %w", err)
	}

	// Encryption subkey binding signature
	encSubkeyBindSig := keySet.MasterKey.BindSubkey(
		keySet.EncryptionSubkey.base,
		keyFlagEncryptCommunications|keyFlagEncryptStorage,
		keySet.EncryptionSubkey.Expiry,
	)
	packets := append(encryptionSubkeyPacket, encSubkeyBindSig.EncodePacket()...)
	return packets, nil
}

// encodeAuthenticationSubkeyPackets encodes the authentication subkey of the KeySet and
// its binding signature as a series of binary OpenPGP packets. Requires the MasterKey
// field to be defined, for creating the binding signature.
//
// If password is not nil and longer than 0 bytes, it is used as a key to
// encrypt the PGP private key packet using the S2K iterated & salted algorithm.
func (keySet *KeySet) encodeAuthenticationSubkeyPackets(password []byte) ([]byte, error) {
	authenticationSubkeyPacket, err := keySet.AuthenticationSubkey.EncodePrivatePacket(password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode authentication subkey packet: %w", err)
	}

	// Authentication subkey binding signature
	authSubkeyBindSig := keySet.MasterKey.BindSubkey(
		keySet.AuthenticationSubkey.base,
		keyFlagAuthenticate,
		keySet.AuthenticationSubkey.Expiry,
	)
	packets := append(authenticationSubkeyPacket, authSubkeyBindSig.EncodePacket()...)
	return packets, nil
}

// encodeSigningSubkeyPackets encodes the signing subkey of the KeySet and
// its binding signature as a series of binary OpenPGP packets. Requires the MasterKey
// field to be defined, for creating the binding signature.
//
// If password is not nil and longer than 0 bytes, it is used as a key to
// encrypt the PGP private key packet using the S2K iterated & salted algorithm.
func (keySet *KeySet) encodeSigningSubkeyPackets(password []byte) ([]byte, error) {
	signingSubkeyPacket, err := keySet.SigningSubkey.EncodePrivatePacket(password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signing subkey packet: %w", err)
	}

	// Signing subkey binding signature
	signSubkeyBindSig := keySet.MasterKey.BindSubkey(
		keySet.SigningSubkey.base,
		keyFlagSign,
		keySet.SigningSubkey.Expiry,
	)
	packets := append(signingSubkeyPacket, signSubkeyBindSig.EncodePacket()...)
	return packets, nil
}

// encodeAllSubkeyPackets encodes the subkeys of the KeySet as a series of binary
// OpenPGP packets. Requires the MasterKey field to be defined, for creating binding
// signatures.
//
// If password is not nil and longer than 0 bytes, it is used as a key to
// encrypt the PGP private key packets using the S2K iterated & salted algorithm.
func (keySet *KeySet) encodeAllSubkeyPackets(password []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Encryption subkey
	if keySet.EncryptionSubkey != nil {
		subkeyPackets, err := keySet.encodeEncryptionSubkeyPackets(password)
		if err != nil {
			return nil, err
		}
		buf.Write(subkeyPackets)
	}

	// Authentication subkey
	if keySet.AuthenticationSubkey != nil {
		subkeyPackets, err := keySet.encodeAuthenticationSubkeyPackets(password)
		if err != nil {
			return nil, err
		}
		buf.Write(subkeyPackets)
	}

	// Signing subkey
	if keySet.SigningSubkey != nil {
		subkeyPackets, err := keySet.encodeSigningSubkeyPackets(password)
		if err != nil {
			return nil, err
		}
		buf.Write(subkeyPackets)
	}

	return buf.Bytes(), nil
}

// encodeSelfCertification creates a self-certification signature by the master key
// and encodes it as a binary OpenPGP packet.
func (keySet *KeySet) encodeSelfCertification() []byte {
	return keySet.MasterKey.SelfCertify(keySet.UserID).EncodePacket()
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

	// Self-certification signature for the master key
	buf.Write(keySet.encodeSelfCertification())

	// Subkeys and binding signatures
	subkeyPackets, err := keySet.encodeAllSubkeyPackets(password)
	if err != nil {
		return nil, err
	}
	buf.Write(subkeyPackets)

	return buf.Bytes(), nil
}

// EncodeSubkeyPackets encodes the KeySet as a series of binary OpenPGP packets,
// but only includes the private key material for subkeys. The master key is
// encoded as a private key stub without providing the private key material itself.
//
// To use the output of this method, the caller is presumed to already have the
// master key, so the self-certification signature is not provided.
//
// If password is not nil and longer than 0 bytes, it is used as a key to
// encrypt the PGP private subkeys using the S2K iterated & salted algorithm.
func (keySet *KeySet) EncodeSubkeyPackets(password []byte, withSelfCert bool) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Dummy master key stub
	buf.Write(keySet.MasterKey.EncodePrivateDummyPacket())

	// User ID
	buf.Write(keySet.UserID.EncodePacket())

	// We might skip the self-certification signature to allow for use cases
	// where the caller already has the master key, so that we don't add useless
	// extra data and clutter their keyring with unneeded signatures.
	if withSelfCert {
		buf.Write(keySet.encodeSelfCertification())
	}

	// Subkeys and binding signatures
	subkeyPackets, err := keySet.encodeAllSubkeyPackets(password)
	if err != nil {
		return nil, err
	}
	buf.Write(subkeyPackets)

	return buf.Bytes(), nil
}
