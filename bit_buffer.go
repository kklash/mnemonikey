package mnemonikey

import (
	"fmt"
	"math/big"
)

// bitBuffer is a utility type for reading and writing leading or trailing bits from a big.Int,
// with a dynamic buffer size tracker.
type bitBuffer struct {
	value *big.Int
	nBits uint
}

func newBitBuffer(value *big.Int, nBits uint) *bitBuffer {
	if bitLen := value.BitLen(); bitLen > int(nBits) {
		panic(fmt.Sprintf("value BitLen %d is larger than buffer size %d", bitLen, nBits))
	}

	return &bitBuffer{
		value: new(big.Int).Set(value),
		nBits: nBits,
	}
}

// PopTrailingBits returns the least significant n bits from the underlying value, and
// shifts the value n bits to the right.
func (bb *bitBuffer) PopTrailingBits(n uint) *big.Int {
	if n > bb.nBits {
		panic(
			fmt.Sprintf(
				"bitBuffer.PopTrailingBits attempted to read outside buffer (size %d) bounds by %d bits",
				bb.nBits,
				n-bb.nBits,
			),
		)
	}

	// mask = ((1 << n) - 1)
	mask := new(big.Int).Lsh(bigOne, n)
	mask.Sub(mask, bigOne)

	// bits = mask & bb.value
	bits := new(big.Int).And(mask, bb.value)

	// Remove the bits from bb.value
	bb.value.Rsh(bb.value, n)
	bb.nBits -= n

	return bits
}

// PopLeadingBits returns the most significant n bits from the underlying value, and
// drops those bits from the value.
func (bb *bitBuffer) PopLeadingBits(n uint) *big.Int {
	if n > bb.nBits {
		panic(
			fmt.Sprintf(
				"bitBuffer.PopLeadingBits attempted to read outside buffer (size %d) bounds by %d bits",
				bb.nBits,
				n-bb.nBits,
			),
		)
	}

	// mask = ((1 << n) - 1)
	mask := new(big.Int).Lsh(bigOne, n)
	mask.Sub(mask, bigOne)

	// bits = mask & (bb.value >> (bb.nBits - n))
	bits := new(big.Int).Rsh(bb.value, bb.nBits-n)
	bits.And(mask, bits)

	// Remove the bits from bb.value
	mask.Lsh(bits, bb.nBits-n)
	bb.value.Xor(bb.value, mask)
	bb.nBits -= n

	return bits
}

// AppendLeadingBits appends the given bits to the leading edge of the bit buffer.
func (bb *bitBuffer) AppendLeadingBits(value *big.Int, nBits uint) {
	if bitLen := value.BitLen(); bitLen > int(nBits) {
		panic(fmt.Sprintf("cannot append %d bit-value as %d bits in buffer", bitLen, nBits))
	}

	// mask = value << bb.nBits
	mask := new(big.Int).Lsh(value, bb.nBits)

	// bb.value |= mask
	bb.value.Or(bb.value, mask)

	bb.nBits += nBits
}

// AppendTrailingBits appends the given bits to the trailing edge of the bit buffer.
func (bb *bitBuffer) AppendTrailingBits(value *big.Int, nBits uint) {
	if bitLen := value.BitLen(); bitLen > int(nBits) {
		panic(fmt.Sprintf("cannot append %d bit-value as %d bits in buffer", bitLen, nBits))
	}

	// bb.value <<= nBits
	bb.value.Lsh(bb.value, nBits)

	// bb.value |= value
	bb.value.Or(bb.value, value)

	bb.nBits += nBits
}

// Bytes returns the byte representation of the bits in the buffer. If the number of bits in the
// buffer is not evenly divisible by 8, the remainder will be left as leading zero bits in the
// leading byte of the returned slice.
func (bb *bitBuffer) Bytes() []byte {
	return bb.value.FillBytes(make([]byte, (bb.nBits+7)/8))
}

// Int returns a copy of the bit buffer value.
func (bb *bitBuffer) Int() *big.Int {
	return new(big.Int).Set(bb.value)
}

// BitLen returns the number of bits currently in the buffer.
func (bb *bitBuffer) BitLen() uint {
	return bb.nBits
}
