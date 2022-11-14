package pgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/curve25519"
)

// oidCurve25519 is the object identifier for Curve25519 encryption keys (OID 1.3.6.1.4.1.3029.1.5.1).
var oidCurve25519 = []byte{
	0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
}

type Curve25519Subkey struct {
	Private  []byte
	Public   []byte
	Birthday time.Time
	Expiry   time.Time
	KDF      *KeyDerivationParameters
}

func NewCurve25519Subkey(
	seed []byte,
	birthday time.Time,
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
		Private:  privateKey,
		Public:   publicKey,
		Birthday: birthday,
		Expiry:   expiry,
		KDF:      kdfParams,
	}
	return key, nil
}

// encodePublic encodes the public key into a serialized payload suitable for
// use in a packet payload.
func (key *Curve25519Subkey) encodePublic() []byte {
	buf := new(bytes.Buffer)

	// Packet version
	buf.WriteByte(keyPacketVersion)

	// Specify key creation time
	binary.Write(buf, binary.BigEndian, uint32(key.Birthday.Unix()))

	// ECC-type public key
	buf.WriteByte(keyAlgorithmECDH)

	// Specify which curve the key uses
	buf.WriteByte(byte(len(oidCurve25519)))
	buf.Write(oidCurve25519)

	// MPI-encoding of public key point
	publicKeyMPI := EncodeMPI(new(big.Int).SetBytes(append([]byte{mpiPrefixEddsaPoint}, key.Public...)))
	buf.Write(publicKeyMPI)

	// KDF parameters
	buf.Write(key.KDF.Encode())

	return buf.Bytes()
}

// EncodePublicPacket encodes the public key into a serialized OpenPGP packet.
func (key *Curve25519Subkey) EncodePublicSubkeyPacket() []byte {
	return EncodePacket(PacketTagPublicSubkey, key.encodePublic())
}

// EncodePrivatePacket encodes the private key into a serialized OpenPGP packet.
func (key *Curve25519Subkey) EncodePrivatePacket(password []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// First include public key in the packet.
	buf.Write(key.encodePublic())

	// package curve25519 represents private keys with little-endian byte slices.
	// reverse this number before exporting to ensure it is interpreted correctly
	// by OpenPGP software, which uses big-endian representations.
	privateKeyBigEndian := reverse(key.Private)

	if len(password) > 0 {
		encrypted, err := EncryptS2K(DefaultStringToKeyHashFunc, privateKeyBigEndian, password)
		if err != nil {
			return nil, err
		}
		buf.Write(encrypted)
	} else {
		// Specify string-to-key usage byte as unencrypted.
		buf.WriteByte(0)

		// MPI-encoded secret key.
		mpiEncodedKey := EncodeMPI(new(big.Int).SetBytes(privateKeyBigEndian))
		buf.Write(mpiEncodedKey)
		buf.Write(checksumMPI(mpiEncodedKey))
	}

	return EncodePacket(PacketTagSecretSubkey, buf.Bytes()), nil
}

func reverse(original []byte) []byte {
	length := len(original)
	reversed := make([]byte, length)
	for i := 0; i < length; i++ {
		reversed[length-i-1] = original[i]
	}
	return reversed
}
