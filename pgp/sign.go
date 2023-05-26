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

	// Subpackets is a collection of extra data which will be committed
	// to by the signature.
	Subpackets []*Subpacket
	Time       time.Time
}

// Sign signs the signature request using the EdDSA algorithm on the
// Edwards 25519 curve.
func Sign(privateKey ed25519.PrivateKey, req *SignatureRequest) *Signature {
	signatureTimestamp := make([]byte, 4)
	binary.BigEndian.PutUint32(signatureTimestamp, uint32(req.Time.Unix()))

	subpackets := []*Subpacket{
		{
			Type: SubpacketTypeCreationTime,
			Body: signatureTimestamp,
		},
		{
			Type: SubpacketTypeIssuerFingerprint,
			Body: append([]byte{keyPacketVersion}, req.SigningKeyFingerprint...),
		},
	}
	subpackets = append(subpackets, req.Subpackets...)

	signature := &Signature{
		HashedSubpackets: subpackets,
		Type:             req.Type,
		HashFunction:     req.HashFunction,
		UnhashedSubpackets: []*Subpacket{
			{
				// TODO remove this if using a key with version 5.
				Type: SubpacketTypeIssuer,
				Body: req.SigningKeyFingerprint[len(req.SigningKeyFingerprint)-8:],
			},
		},
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
