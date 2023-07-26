package pgp

import (
	"crypto/ed25519"
	"encoding/binary"
	"math/big"
	"time"
)

// SignatureRequest is the input data needed for an OpenPGP signature.
type SignatureRequest struct {
	// SigningKeyFingerprint is the fingerprint of the signing PGP key.
	SigningKeyFingerprint []byte

	// HashFunction describes how the final data block should be hashed
	// to prepare it for EdDSA signing.
	HashFunction HashFuncID

	// Data is the arbitrary context-dependent data to be signed.
	Data []byte

	// Type describes what kind of signature should be made.
	Type SignatureType

	// HashedSubpackets is a collection of extra data which will be committed
	// to by the signature.
	HashedSubpackets []*Subpacket

	// UnhashedSubpackets is a collection of extra subpackets which are not
	// committed to by the signature.
	UnhashedSubpackets []*Subpacket

	// Time is the timestamp when the signature is created.
	Time time.Time
}

// Sign signs the signature request using the EdDSA algorithm on the
// Edwards 25519 curve.
func Sign(privateKey ed25519.PrivateKey, req *SignatureRequest) *Signature {
	signatureTimestamp := make([]byte, 4)
	binary.BigEndian.PutUint32(signatureTimestamp, uint32(req.Time.Unix()))

	hashedSubpackets := []*Subpacket{
		{
			Type: SubpacketTypeIssuerFingerprint,
			Body: append([]byte{keyPacketVersion}, req.SigningKeyFingerprint...),
		},
		{
			Type: SubpacketTypeCreationTime,
			Body: signatureTimestamp,
		},
	}
	hashedSubpackets = append(hashedSubpackets, req.HashedSubpackets...)

	unhashedSubpackets := []*Subpacket{
		{
			// TODO remove this if using a key with version 5.
			Type: SubpacketTypeIssuer,
			Body: req.SigningKeyFingerprint[len(req.SigningKeyFingerprint)-8:],
		},
	}
	unhashedSubpackets = append(unhashedSubpackets, req.UnhashedSubpackets...)

	signature := &Signature{
		HashedSubpackets:   hashedSubpackets,
		Type:               req.Type,
		HashFunction:       req.HashFunction,
		UnhashedSubpackets: unhashedSubpackets,
	}

	h := req.HashFunction.New()
	h.Write(req.Data)
	signatureHashPreimage := signature.encodePreimage()
	h.Write(signatureHashPreimage)
	h.Write(signatureTrailer)
	binary.Write(h, binary.BigEndian, uint32(len(signatureHashPreimage)))

	signature.SigHash = h.Sum(nil)
	encodedSig := ed25519.Sign(privateKey, signature.SigHash)

	signature.R = new(big.Int).SetBytes(encodedSig[:32])
	signature.S = new(big.Int).SetBytes(encodedSig[32:])
	return signature
}
