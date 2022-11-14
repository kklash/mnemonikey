package pgp

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

const (
	keyPacketVersion byte = 4
	sigPacketVersion byte = 4

	mpiPrefixEddsaPoint byte = 0x40

	s2kCountMaximum byte = 0xFF

	publicKeyPrefixV4          byte = 0x99
	userIDPrefix               byte = 0xB4
	stringToKeySpecifierPrefix byte = 254

	keyAlgorithmECDH  byte = 18
	keyAlgorithmEDDSA byte = 22

	keyFlagCertify               byte = 0b00000001
	keyFlagSign                  byte = 0b00000010
	keyFlagEncryptCommunications byte = 0b00000100
	keyFlagEncryptStorage        byte = 0b00001000
	keyFlagAuthenticate          byte = 0b00100000

	stringToKeyUsageSimple            byte = 1
	stringToKeyUsageSalted            byte = 2
	stringToKeyUsageIteratedAndSalted byte = 3
)

var signatureTrailer = []byte{sigPacketVersion, 0xFF}

var (
	// DefaultKDFParameters are the default key derivation parameters used when constructing
	// encryption keys.
	DefaultKDFParameters = &KeyDerivationParameters{
		HashFunction:    HashFuncSHA256,
		CipherAlgorithm: CipherAlgoAES256,
	}

	// DefaultStringToKeyHashFunc is the default string-to-key (S2K) hash function.
	DefaultStringToKeyHashFunc = HashFuncSHA256
)

type HashFuncID byte

const (
	HashFuncSHA256 HashFuncID = 8
	HashFuncSHA384 HashFuncID = 9
	HashFuncSHA512 HashFuncID = 10
)

func (id HashFuncID) New() hash.Hash {
	switch id {
	case HashFuncSHA256:
		return sha256.New()
	case HashFuncSHA384:
		return sha512.New384()
	case HashFuncSHA512:
		return sha512.New()
	}
	return nil
}

type CipherAlgoID byte

const (
	CipherAlgoAES128 CipherAlgoID = 7
	CipherAlgoAES192 CipherAlgoID = 8
	CipherAlgoAES256 CipherAlgoID = 9
)

type KeyDerivationParameters struct {
	HashFunction    HashFuncID
	CipherAlgorithm CipherAlgoID
}

func (kdf *KeyDerivationParameters) Encode() []byte {
	return []byte{
		3, // length
		1, // reserved
		byte(kdf.HashFunction),
		byte(kdf.CipherAlgorithm),
	}
}

// SignatureType denotes the intent of a signature.
//
//	https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#section-5.2.1
type SignatureType byte

const (
	SignatureTypePositiveCertification SignatureType = 0x13
	SignatureTypeSubkeyBinding         SignatureType = 0x18
)

type PacketTag byte

const (
	PacketTagSignature    PacketTag = 2
	PacketTagSecretKey    PacketTag = 5
	PacketTagPublicKey    PacketTag = 6
	PacketTagSecretSubkey PacketTag = 7
	PacketTagUserID       PacketTag = 13
	PacketTagPublicSubkey PacketTag = 14
)

type SubpacketType byte

const (
	SubpacketTypeCreationTime      SubpacketType = 2
	SubpacketTypeExpiry            SubpacketType = 9
	SubpacketTypeIssuer            SubpacketType = 16
	SubpacketTypeKeyFlags          SubpacketType = 27
	SubpacketTypeFeatures          SubpacketType = 30
	SubpacketTypeIssuerFingerprint SubpacketType = 33
)
