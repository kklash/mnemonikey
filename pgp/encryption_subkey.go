package pgp

import (
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
)

// oidCurve25519 is the object identifier for Curve25519 encryption keys (OID 1.3.6.1.4.1.3029.1.5.1).
var oidCurve25519 = []byte{
	0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
}

// Curve25519Subkey represents an OpenPGP X25519 Diffie-Hellman encryption subkey.
type Curve25519Subkey struct {
	base     *ellipticCurveKey
	Private  []byte
	Public   []byte
	Creation time.Time
	Expiry   time.Time
	KDF      *KeyDerivationParameters
}

// NewCurve25519Subkey derives an X25519 encryption subkey from the given
// 32-byte seed, and sets the given key creation and expiry dates.
//
// If kdfParams is nil, DefaultKDFParameters is used instead.
func NewCurve25519Subkey(
	seed []byte,
	creation time.Time,
	expiry time.Time,
	kdfParams *KeyDerivationParameters,
) (*Curve25519Subkey, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("unexpected curve25519 seed length %d", len(seed))
	}

	// Clamp the private key as per Curve25519 spec
	privateKey := append([]byte{}, seed...)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err := curve25519.X25519(seed, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	if kdfParams == nil {
		kdfParams = DefaultKDFParameters
	}

	key := &Curve25519Subkey{
		base: &ellipticCurveKey{
			// package curve25519 represents private keys with little-endian byte slices.
			// reverse this number before exporting to ensure it is interpreted correctly
			// by OpenPGP software, which uses big-endian representations.
			PrivateSerialized: reverse(privateKey),
			PublicSerialized:  publicKey,

			Creation:        creation,
			Algorithm:       keyAlgorithmECDH,
			CurveOID:        oidCurve25519,
			ExtraPublicData: kdfParams.Encode(),
		},
		Private:  privateKey,
		Public:   publicKey,
		Creation: creation,
		Expiry:   expiry,
		KDF:      kdfParams,
	}
	return key, nil
}

// FingerprintV4 returns the 20-byte SHA1 hash of the serialized public key.
func (key *Curve25519Subkey) FingerprintV4() []byte {
	return key.base.FingerprintV4()
}

// EncodePublicSubkeyPacket encodes the public key into a serialized OpenPGP packet.
func (key *Curve25519Subkey) EncodePublicSubkeyPacket() []byte {
	return EncodePacket(PacketTagPublicSubkey, key.base.encodePublic())
}

// EncodePrivatePacket encodes the private key into a serialized OpenPGP packet.
func (key *Curve25519Subkey) EncodePrivatePacket(password []byte) ([]byte, error) {
	encodedPrivateKey, err := key.base.encodePrivate(password)
	if err != nil {
		return nil, err
	}
	return EncodePacket(PacketTagSecretSubkey, encodedPrivateKey), nil
}

func reverse(original []byte) []byte {
	length := len(original)
	reversed := make([]byte, length)
	for i := 0; i < length; i++ {
		reversed[length-i-1] = original[i]
	}
	return reversed
}
