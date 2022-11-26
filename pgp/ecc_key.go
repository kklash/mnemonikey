package pgp

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"time"
)

// ellipticCurveKey is used to abstract away the the common encoding of elliptic curve
// private and public keys in OpenPGP format.
type ellipticCurveKey struct {
	Private         []byte
	Public          []byte
	Creation        time.Time
	Algorithm       byte
	CurveOID        []byte
	ExtraPublicData []byte
}

// encodePublic encodes the public key into a serialized payload suitable for
// use in a packet payload.
func (key *ellipticCurveKey) encodePublic() []byte {
	buf := new(bytes.Buffer)

	// Packet version
	buf.WriteByte(keyPacketVersion)

	// Specify key creation time
	binary.Write(buf, binary.BigEndian, uint32(key.Creation.Unix()))

	// Describe use purpose of public key
	buf.WriteByte(key.Algorithm)

	// Specify which curve the key uses
	buf.WriteByte(byte(len(key.CurveOID)))
	buf.Write(key.CurveOID)

	// MPI-encoding of public key point
	publicKeyMPI := EncodeMPI(
		new(big.Int).SetBytes(append([]byte{mpiPrefixEddsaPoint}, key.Public...)),
	)
	buf.Write(publicKeyMPI)

	if key.ExtraPublicData != nil {
		buf.Write(key.ExtraPublicData)
	}

	return buf.Bytes()
}

// encodePrivate encodes the private key into a serialized payload suitable for
// use in a packet payload.
func (key *ellipticCurveKey) encodePrivate(password []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// First include public key in the packet.
	buf.Write(key.encodePublic())

	if len(password) > 0 {
		encrypted, err := EncryptS2K(DefaultStringToKeyHashFunc, key.Private, password)
		if err != nil {
			return nil, err
		}
		buf.Write(encrypted)
	} else {
		// Specify string-to-key usage byte as unencrypted.
		buf.WriteByte(0)

		// MPI-encoded secret key.
		mpiEncodedKey := EncodeMPI(new(big.Int).SetBytes(key.Private))
		buf.Write(mpiEncodedKey)
		buf.Write(checksumMPI(mpiEncodedKey))
	}

	return buf.Bytes(), nil
}
