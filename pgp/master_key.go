package pgp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

// oidED25519 is the object identifier for ED25519 signing keys (OID 1.3.6.1.4.1.11591.15.1).
var oidED25519 = []byte{
	0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01,
}

type ED25519MasterKey struct {
	Private  ed25519.PrivateKey
	Public   ed25519.PublicKey
	Birthday time.Time
	Expiry   time.Time
}

func NewED25519MasterKey(seed []byte, birthday, expiry time.Time) (*ED25519MasterKey, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("unexpected ed25519 seed length %d", len(seed))
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	key := &ED25519MasterKey{
		Private:  privateKey,
		Public:   publicKey,
		Birthday: birthday,
		Expiry:   expiry,
	}
	return key, nil
}

// encodePublic encodes the public key into a serialized payload suitable for
// use in a packet payload.
func (key *ED25519MasterKey) encodePublic() []byte {
	buf := new(bytes.Buffer)

	// Packet version
	buf.WriteByte(keyPacketVersion)

	// Specify key creation time
	binary.Write(buf, binary.BigEndian, uint32(key.Birthday.Unix()))

	// ECC-type public key
	buf.WriteByte(keyAlgorithmEDDSA)

	// Specify which curve the key uses
	buf.WriteByte(byte(len(oidED25519)))
	buf.Write(oidED25519)

	// MPI-encoding of public key point
	publicKeyMPI := EncodeMPI(new(big.Int).SetBytes(append([]byte{mpiPrefixEddsaPoint}, key.Public...)))
	buf.Write(publicKeyMPI)

	return buf.Bytes()
}

func (key *ED25519MasterKey) FingerprintV4() []byte {
	publicKeyPayload := key.encodePublic()

	h := sha1.New()
	h.Write([]byte{publicKeyPrefixV4})
	binary.Write(h, binary.BigEndian, uint16(len(publicKeyPayload)))
	h.Write(publicKeyPayload)

	return h.Sum(nil)
}

// EncodePublicPacket encodes the public key into a serialized OpenPGP packet.
func (key *ED25519MasterKey) EncodePublicSubkeyPacket() []byte {
	return EncodePacket(PacketTagPublicKey, key.encodePublic())
}

// EncodePrivatePacket encodes the private key into a serialized OpenPGP packet.
func (key *ED25519MasterKey) EncodePrivatePacket(password []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// First include public key in the packet.
	buf.Write(key.encodePublic())

	// package ed25519 represents private keys as the concatenation of private and
	// public keys. Trim off the public part before exporting.
	privateKey := key.Private[:32]

	if len(password) > 0 {
		encrypted, err := EncryptS2K(DefaultStringToKeyHashFunc, privateKey, password)
		if err != nil {
			return nil, err
		}
		buf.Write(encrypted)
	} else {
		// Specify string-to-key usage byte as unencrypted.
		buf.WriteByte(0)

		// MPI-encoded secret key.
		mpiEncodedKey := EncodeMPI(new(big.Int).SetBytes(privateKey))
		buf.Write(mpiEncodedKey)
		buf.Write(checksumMPI(mpiEncodedKey))
	}

	return EncodePacket(PacketTagSecretKey, buf.Bytes()), nil
}

type SignatureRequest struct {
	HashFunction HashFuncID
	Data         []byte
	Type         SignatureType
	Subpackets   []*Subpacket
	Time         time.Time
}

func (key *ED25519MasterKey) Sign(req *SignatureRequest) *Signature {
	fingerprint := key.FingerprintV4()
	signatureTimestamp := make([]byte, 4)
	binary.BigEndian.PutUint32(signatureTimestamp, uint32(req.Time.Unix()))

	subpackets := []*Subpacket{
		{
			Type: SubpacketTypeCreationTime,
			Body: signatureTimestamp,
		},
		{
			// TODO do we need this subpacket?
			Type: SubpacketTypeIssuer,
			Body: fingerprint[len(fingerprint)-8:],
		},
		{
			Type: SubpacketTypeIssuerFingerprint,
			Body: append([]byte{keyPacketVersion}, fingerprint...),
		},
	}
	subpackets = append(subpackets, req.Subpackets...)

	signature := &Signature{
		HashedSubpackets: subpackets,
		Type:             req.Type,
		HashFunction:     req.HashFunction,
	}

	h := req.HashFunction.New()
	h.Write(req.Data)
	signatureHashPreimage := signature.encodePreimage()
	h.Write(signatureHashPreimage)
	h.Write(signatureTrailer)
	binary.Write(h, binary.BigEndian, uint32(len(signatureHashPreimage)))

	signature.SigHash = h.Sum(nil)
	encodedSig := ed25519.Sign(key.Private, signature.SigHash)

	signature.R = new(big.Int).SetBytes(encodedSig[:32])
	signature.S = new(big.Int).SetBytes(encodedSig[32:])
	return signature
}

func (key *ED25519MasterKey) SelfCertify(userID *UserID) *Signature {
	publicKeyPayload := key.encodePublic()
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

	subpackets := []*Subpacket{
		{
			Type: SubpacketTypeKeyFlags,
			Body: []byte{keyFlagCertify | keyFlagSign},
		},
		{
			// TODO do we need this subpacket?
			Type: SubpacketTypeFeatures,
			Body: []byte{1}, // Enable MDC
		},
	}

	if !key.Expiry.IsZero() {
		expiryTime := make([]byte, 4)
		binary.BigEndian.PutUint32(expiryTime, uint32(key.Expiry.Sub(key.Birthday).Seconds()))
		subpackets = append(subpackets, &Subpacket{
			Type: SubpacketTypeExpiry,
			Body: expiryTime,
		})
	}

	return key.Sign(&SignatureRequest{
		HashFunction: HashFuncSHA256,
		Data:         buf.Bytes(),
		Type:         SignatureTypePositiveCertification,
		Subpackets:   subpackets,
		Time:         key.Birthday,
	})
}

func (key *ED25519MasterKey) BindSubkey(subkey *Curve25519Subkey) *Signature {
	parentPublicPayload := key.encodePublic()
	subkeyPublicPayload := subkey.encodePublic()

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
			Body: []byte{keyFlagEncryptCommunications | keyFlagEncryptStorage},
		},
	}

	if !subkey.Expiry.IsZero() {
		expiryTime := make([]byte, 4)
		binary.BigEndian.PutUint32(expiryTime, uint32(subkey.Expiry.Sub(subkey.Birthday).Seconds()))
		subpackets = append(subpackets, &Subpacket{
			Type: SubpacketTypeExpiry,
			Body: expiryTime,
		})
	}

	return key.Sign(&SignatureRequest{
		HashFunction: HashFuncSHA256,
		Data:         buf.Bytes(),
		Type:         SignatureTypeSubkeyBinding,
		Subpackets:   subpackets,
		Time:         subkey.Birthday,
	})
}
