package pgp

import "encoding/binary"

// EncodePacket encodes a binary Packet according to the generic OpenPGP
// packet encoding protocol.
//
//	https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#section-4.2
func EncodePacket(tag PacketTag, payload []byte) []byte {
	payloadSize := len(payload)
	lengthEncoded := packetLengthEncode(payloadSize)

	encoded := make([]byte, 1+len(lengthEncoded)+payloadSize)
	encoded[0] = 0b11000000 | byte(tag)
	copy(encoded[1:], lengthEncoded)
	copy(encoded[1+len(lengthEncoded):], payload)

	return encoded
}

func packetLengthEncode(payloadSize int) []byte {
	if payloadSize <= 191 {
		return []byte{byte(payloadSize)}
	}

	if payloadSize <= 8383 {
		k := payloadSize - 192
		return []byte{byte(k>>8) + 192, byte(k)}
	}

	lengthEncoded := []byte{0xFF, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(lengthEncoded[1:], uint32(payloadSize))
	return lengthEncoded
}
