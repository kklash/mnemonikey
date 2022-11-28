package pgp

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// ED25519Subkey represents an OpenPGP ED25519 authentication subkey.
type ED25519Subkey struct {
	base     *ellipticCurveKey
	Private  ed25519.PrivateKey
	Public   ed25519.PublicKey
	Creation time.Time
	Expiry   time.Time
}

// ED25519Subkey derives an ED25519 authentication subkey from the given
// 32-byte seed, and sets the given key creation and expiry dates.
func NewED25519Subkey(seed []byte, creation time.Time, expiry time.Time) (*ED25519Subkey, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("unexpected ed25519 seed length %d", len(seed))
	}

	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	key := &ED25519Subkey{
		base: &ellipticCurveKey{
			// package ed25519 represents private keys as the concatenation of private and
			// public keys. Trim off the public part before exporting.
			PrivateSerialized: privateKey[:32],
			PublicSerialized:  publicKey,

			PrivateSigning: privateKey,
			PublicSigning:  publicKey,

			Creation:  creation,
			Algorithm: keyAlgorithmEDDSA,
			CurveOID:  oidED25519,
		},

		Private:  privateKey,
		Public:   publicKey,
		Creation: creation,
		Expiry:   expiry,
	}
	return key, nil
}

// FingerprintV4 returns the 20-byte SHA1 hash of the serialized public key.
func (key *ED25519Subkey) FingerprintV4() []byte {
	return key.base.FingerprintV4()
}

// EncodePublicPacket encodes the public key into a serialized OpenPGP packet.
func (key *ED25519Subkey) EncodePublicSubkeyPacket() []byte {
	return EncodePacket(PacketTagPublicSubkey, key.base.encodePublic())
}

// EncodePrivatePacket encodes the private key into a serialized OpenPGP packet.
func (key *ED25519Subkey) EncodePrivatePacket(password []byte) ([]byte, error) {
	encodedPrivateKey, err := key.base.encodePrivate(password)
	if err != nil {
		return nil, err
	}
	return EncodePacket(PacketTagSecretSubkey, encodedPrivateKey), nil
}
