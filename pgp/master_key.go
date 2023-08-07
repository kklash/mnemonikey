package pgp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"time"
)

// oidED25519 is the object identifier for ED25519 signing keys (OID 1.3.6.1.4.1.11591.15.1).
var oidED25519 = []byte{
	0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01,
}

// ED25519MasterKey represents an OpenPGP ED25519 EdDSA signing and certification master key.
type ED25519MasterKey struct {
	base     *ellipticCurveKey
	Private  ed25519.PrivateKey
	Public   ed25519.PublicKey
	Creation time.Time
	Expiry   time.Time
}

// NewED25519MasterKey derives an ED25519 signing master key from the given 32-byte seed,
// and sets the given key creation and expiry dates.
func NewED25519MasterKey(seed []byte, creation, expiry time.Time) (*ED25519MasterKey, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("unexpected ed25519 seed length %d", len(seed))
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	key := &ED25519MasterKey{
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
func (key *ED25519MasterKey) FingerprintV4() []byte {
	return key.base.FingerprintV4()
}

// EncodePublicPacket encodes the public key into a serialized OpenPGP packet.
func (key *ED25519MasterKey) EncodePublicPacket() []byte {
	return EncodePacket(PacketTagPublicKey, key.base.encodePublic())
}

// EncodePrivatePacket encodes the private key into a serialized OpenPGP packet.
func (key *ED25519MasterKey) EncodePrivatePacket(password []byte) ([]byte, error) {
	encodedPrivateKey, err := key.base.encodePrivate(password)
	if err != nil {
		return nil, err
	}
	return EncodePacket(PacketTagSecretKey, encodedPrivateKey), nil
}

// EncodePrivateDummyPacket encodes the public key and a private key stub into
// a serialized OpenPGP packet.
func (key *ED25519MasterKey) EncodePrivateDummyPacket() []byte {
	return EncodePacket(PacketTagSecretKey, key.base.encodePrivateDummy())
}

// SelfCertify returns a self-certification signature, needed
// to prove the key attests to being owned by a given user identifier.
func (key *ED25519MasterKey) SelfCertify(userID *UserID) *Signature {

	publicKeyPayload := key.base.encodePublic()
	userIDPayload := userID.Encode()

	buf := new(bytes.Buffer)

	// Commit to the public key
	buf.WriteByte(publicKeyPrefixV4)
	binary.Write(buf, binary.BigEndian, uint16(len(publicKeyPayload)))
	buf.Write(publicKeyPayload)

	// Commit to the user ID
	buf.WriteByte(userIDPrefix)
	binary.Write(buf, binary.BigEndian, uint32(len(userIDPayload)))
	buf.Write(userIDPayload)

	// Signed subpackets should use the same ordering as default GPG keys.
	// - Issuer fingerprint (added by the Sign() function)
	// - Signature time (added by the Sign() function)
	// - Key flags
	// - Expiry
	// - Cipher preferences
	// - Hash preferences
	// - Compression preferences
	// - Features (MDC)
	// - Key server preferences

	subpackets := []*Subpacket{
		{
			Type: SubpacketTypeKeyFlags,
			Body: []byte{keyFlagCertify},
		},
	}

	if !key.Expiry.IsZero() {
		expiryTime := make([]byte, 4)
		binary.BigEndian.PutUint32(expiryTime, uint32(key.Expiry.Sub(key.Creation).Seconds()))
		subpackets = append(subpackets, &Subpacket{
			Type: SubpacketTypeExpiry,
			Body: expiryTime,
		})
	}

	subpackets = append(subpackets,
		// Use the same preferred cipher, hash, and compression algorithms as default GPG keys.
		&Subpacket{
			Type: SubpacketTypePreferredCipherAlgorithms,
			Body: []byte{
				byte(CipherAlgoAES256),
				byte(CipherAlgoAES192),
				byte(CipherAlgoAES128),
				byte(CipherAlgoDES),
			},
		},
		&Subpacket{
			Type: SubpacketTypePreferredHashAlgorithms,
			Body: []byte{
				byte(HashFuncSHA512),
				byte(HashFuncSHA384),
				byte(HashFuncSHA256),
				byte(HashFuncSHA224),
				byte(HashFuncSHA1),
			},
		},
		&Subpacket{
			Type: SubpacketTypePreferredCompressionAlgorithms,
			Body: []byte{
				byte(CompressionAlgoZLIB),
				byte(CompressionAlgoBZIP2),
				byte(CompressionAlgoZIP),
			},
		},

		// Enable MDC. "AEAD encryption or a Modification Detection Code (MDC)
		// MUST be used anytime the symmetric key is protected by ECDH."
		// https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-ec-dh-algorithm-ecdh
		&Subpacket{
			Type: SubpacketTypeFeatures,
			Body: []byte{1},
		},
		&Subpacket{
			Type: SubpacketTypeKeyServerPreferences,
			Body: []byte{keyServerNoModifyFlag},
		},
	)

	return Sign(
		key.Private,
		&SignatureRequest{
			SigningKeyFingerprint: key.FingerprintV4(),
			HashFunction:          HashFuncSHA256,
			Data:                  buf.Bytes(),
			Type:                  SignatureTypePositiveCertification,
			HashedSubpackets:      subpackets,
			Time:                  key.Creation,
		},
	)
}

// BindSubkey returns a subkey binding signature on the given encryption subkey.
func (key *ED25519MasterKey) BindSubkey(
	subkeyBase *ellipticCurveKey,
	keyFlags byte,
	expiry time.Time,
) *Signature {
	parentPublicPayload := key.base.encodePublic()
	subkeyPublicPayload := subkeyBase.encodePublic()

	buf := new(bytes.Buffer)

	// Commit to the signing key
	buf.WriteByte(publicKeyPrefixV4)
	binary.Write(buf, binary.BigEndian, uint16(len(parentPublicPayload)))
	buf.Write(parentPublicPayload)

	// Commit to the subkey
	buf.WriteByte(publicKeyPrefixV4)
	binary.Write(buf, binary.BigEndian, uint16(len(subkeyPublicPayload)))
	buf.Write(subkeyPublicPayload)

	subpackets := []*Subpacket{
		{
			Type: SubpacketTypeKeyFlags,
			Body: []byte{keyFlags},
		},
	}

	if !expiry.IsZero() {
		expiryTime := make([]byte, 4)
		binary.BigEndian.PutUint32(expiryTime, uint32(expiry.Sub(subkeyBase.Creation).Seconds()))
		subpackets = append(subpackets, &Subpacket{
			Type: SubpacketTypeExpiry,
			Body: expiryTime,
		})
	}

	// cross-certification: binds the subkey to the master key to confirm they are
	// owned by the same person. See: https://gnupg.org/faq/subkey-cross-certify.html
	var unhashedSubpackets []*Subpacket
	if keyFlags&keyFlagSign != 0 {
		if subkeyBase.PrivateSigning == nil {
			panic("attempting to bind to signing key, but signing key doesn't have an ed25519.PrivateKey")
		}
		unhashedSubpackets = []*Subpacket{{
			Type: SubpacketTypeEmbeddedSignature,
			Body: Sign(
				subkeyBase.PrivateSigning,
				&SignatureRequest{
					SigningKeyFingerprint: subkeyBase.FingerprintV4(),
					HashFunction:          HashFuncSHA256,
					Data:                  buf.Bytes(),
					Type:                  SignatureTypePrimaryKeyBinding,
					Time:                  subkeyBase.Creation,
				},
			).Encode(),
		}}
	}

	return Sign(
		key.Private,
		&SignatureRequest{
			SigningKeyFingerprint: key.FingerprintV4(),
			HashFunction:          HashFuncSHA256,
			Data:                  buf.Bytes(),
			Type:                  SignatureTypeSubkeyBinding,
			HashedSubpackets:      subpackets,
			UnhashedSubpackets:    unhashedSubpackets,
			Time:                  subkeyBase.Creation,
		},
	)
}
