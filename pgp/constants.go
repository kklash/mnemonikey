package pgp

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

const (
	// Packet versions for compatibility and decoding.
	keyPacketVersion byte = 4
	sigPacketVersion byte = 4

	// mpiPrefixEddsaPoint is prepended to every encoded EDDSA curve point.
	mpiPrefixEddsaPoint byte = 0x40

	// s2kCountMaximum is the maximum number of salted iterations the S2K algorithm
	// can support.
	s2kCountMaximum byte = 0xFF

	// s2kExtensionGNUDummy is an extension used for encoding private key stubs.
	// This is used to export private subkeys without the master private key.
	s2kExtensionGNUDummy byte = 101
	s2kGNUExtensionID         = "GNU"

	// These prefixes are prepended before data to be hashed, usually to ensure hash
	// preimage namespacing.
	publicKeyPrefixV4 byte = 0x99
	publicKeyPrefixV5 byte = 0x9A
	userIDPrefix      byte = 0xB4

	// This specifier tells OpenPGP the expected algorithm needed to decrypt an S2K
	// encrypted key.
	stringToKeySpecifierPrefix byte = 254

	// These are algorithm specifiers used to describe the format of a key in an
	// OpenPGP packet.
	keyAlgorithmECDH  byte = 18
	keyAlgorithmEDDSA byte = 22

	// These flags indicate the purpose of a PGP key.
	// Normally a key will be used for either signing,
	// certifying, encrypting, or authenticating.
	keyFlagCertify               byte = 0b00000001
	keyFlagSign                  byte = 0b00000010
	keyFlagEncryptCommunications byte = 0b00000100
	keyFlagEncryptStorage        byte = 0b00001000
	keyFlagAuthenticate          byte = 0b00100000

	// These bytes indicate the procedure used to encrypt keys in PGP keychains
	// and in serialized OpenPGP packets.
	stringToKeyUsageSimple            byte = 1
	stringToKeyUsageSalted            byte = 2
	stringToKeyUsageIteratedAndSalted byte = 3
)

// signatureTrailer is included in every binding and certification
// signature hash preimage.
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

// HashFuncID identifies a hash function within OpenPGP packets.
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

// CipherAlgoID identifies a symmetric encryption algorithm within OpenPGP packets.
type CipherAlgoID byte

const (
	CipherAlgoAES128 CipherAlgoID = 7
	CipherAlgoAES192 CipherAlgoID = 8
	CipherAlgoAES256 CipherAlgoID = 9
)

// KeyDerivationParameters represents a set of key-derivation parameters included within
// public key packets. These parameters are included in serialized encryption subkeys.
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

	// SignatureTypePositiveCertification indicates the signature intends to certify
	// that a given public key belongs to a given user identity.
	SignatureTypePositiveCertification SignatureType = 0x13

	// SignatureTypeSubkeyBinding indicates the signature intends to bind a subkey to
	// a master certification key.
	SignatureTypeSubkeyBinding SignatureType = 0x18

	// SignatureTypePrimaryKeyBinding indicates the signature intends to bind a master
	// key to a signing subkey.
	SignatureTypePrimaryKeyBinding SignatureType = 0x19

	// Assorted signature types not used by this library but exported for optional
	// downstream funcionality extensions.
	SignatureTypeBinaryDocument         SignatureType = 0x00
	SignatureTypeTextDocument           SignatureType = 0x01
	SignatureTypeStandalone             SignatureType = 0x02
	SignatureTypeGenericCertification   SignatureType = 0x10
	SignatureTypePersonaCertification   SignatureType = 0x11
	SignatureTypeCasualCertification    SignatureType = 0x12
	SignatureTypeAttestedKey            SignatureType = 0x16
	SignatureTypeDirectKey              SignatureType = 0x1F
	SignatureTypeRevocation             SignatureType = 0x20
	SignatureTypeSubkeyRevocation       SignatureType = 0x28
	SignatureTypeCertifiationRevocation SignatureType = 0x30
	SignatureTypeTimestamp              SignatureType = 0x40
	SignatureTypeThirdPartyConfirmation SignatureType = 0x50
)

// PacketTag is included in the header of every OpenPGP packet. It indicates
// the type of OpenPGP packet that follows, and how to decode it.
type PacketTag byte

const (
	PacketTagSignature    PacketTag = 2
	PacketTagSecretKey    PacketTag = 5
	PacketTagPublicKey    PacketTag = 6
	PacketTagSecretSubkey PacketTag = 7
	PacketTagUserID       PacketTag = 13
	PacketTagPublicSubkey PacketTag = 14
)

// SubpacketType identifies the meaning of a subpacket in an
// OpenPGP signature packet.
type SubpacketType byte

const (
	SubpacketTypeCreationTime                   SubpacketType = 2
	SubpacketTypeExpiry                         SubpacketType = 9
	SubpacketTypePreferredCipherAlgorithms      SubpacketType = 11
	SubpacketTypeIssuer                         SubpacketType = 16
	SubpacketTypePreferredHashAlgorithms        SubpacketType = 21
	SubpacketTypePreferredCompressionAlgorithms SubpacketType = 22
	SubpacketTypeKeyFlags                       SubpacketType = 27
	SubpacketTypeFeatures                       SubpacketType = 30
	SubpacketTypeEmbeddedSignature              SubpacketType = 32
	SubpacketTypeIssuerFingerprint              SubpacketType = 33
	SubpacketTypePreferredAEADAlgorithms        SubpacketType = 34
)
