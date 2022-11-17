package pgp

import (
	"bytes"
	"encoding/binary"
	"math/big"
)

// Subpackets contain extra metadata about the conditions of a signature's
// assertion, and they may or may not be committed to by the signature,
// depending on their position within the signature packet.
type Subpacket struct {
	Type SubpacketType
	Body []byte
}

// Encode returns the binary encoding of the Subpacket.
func (sp *Subpacket) Encode() []byte {
	buf := new(bytes.Buffer)
	buf.Write(packetLengthEncode(len(sp.Body) + 1))
	buf.WriteByte(byte(sp.Type))
	buf.Write(sp.Body)
	return buf.Bytes()
}

func encodeSubpackets(subpackets []*Subpacket) []byte {
	encoded := make([]byte, 2)
	for _, sp := range subpackets {
		encoded = append(encoded, sp.Encode()...)
	}
	binary.BigEndian.PutUint16(encoded, uint16(len(encoded)-2))
	return encoded
}

// Signature represents an OpenPGP EdDSA signature.
type Signature struct {
	HashedSubpackets   []*Subpacket
	UnhashedSubpackets []*Subpacket
	Type               SignatureType
	HashFunction       HashFuncID
	SigHash            []byte
	R, S               *big.Int
}

// encodePreimage encodes the signature hash preimage trailer, needed to
// produce the signature. This does not include the main body of the
// data to be signed.
func (signature *Signature) encodePreimage() []byte {
	buf := new(bytes.Buffer)

	// Packet version
	buf.WriteByte(sigPacketVersion)

	// Signature type. Shows what the signature is intended to affirm.
	buf.WriteByte(byte(signature.Type))

	// Signature Algorithm
	buf.WriteByte(keyAlgorithmEDDSA)

	// Hash function
	buf.WriteByte(byte(signature.HashFunction))

	// Subpackets
	buf.Write(encodeSubpackets(signature.HashedSubpackets))

	return buf.Bytes()
}

// Encode returns the binary encoding of the signature hash preimage trailer
// and the EdDSA signature value pair (r, s).
func (signature *Signature) Encode() []byte {
	buf := new(bytes.Buffer)

	// Signature hash preimage
	buf.Write(signature.encodePreimage())

	// Unhashed subpackets
	buf.Write(encodeSubpackets(signature.UnhashedSubpackets))

	// Hash preview
	buf.Write(signature.SigHash[:2])

	// Signature
	buf.Write(EncodeMPI(signature.R))
	buf.Write(EncodeMPI(signature.S))

	return buf.Bytes()
}

func (signature *Signature) EncodePacket() []byte {
	return EncodePacket(PacketTagSignature, signature.Encode())
}
