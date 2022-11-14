package pgp

import (
	"encoding/binary"
	"math/big"
)

// EncodeMPI encodes a given integer as a multiprecision integer according
// to the OpenPGP protocol.
//
//	https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#section-3.2
func EncodeMPI(n *big.Int) []byte {
	bitLen := n.BitLen()
	outLen := (bitLen+7)/8 + 2
	encoded := make([]byte, outLen)

	binary.BigEndian.PutUint16(encoded, uint16(bitLen))
	copy(encoded[2:], n.Bytes())

	return encoded
}

// checksumMPI returns a checksum of the given MPI data, via byte addition modulo 0xFFFF.
func checksumMPI(mpi []byte) []byte {
	var checksum uint16
	for _, b := range mpi {
		checksum += uint16(b)
	}
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], checksum)
	return buf[:]
}
