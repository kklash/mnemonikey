package mnemonikey

import (
	"bytes"
	"math/big"
	"strings"
	"testing"
)

func shouldPanicWith(t *testing.T, expectedPanicString string, fn func()) {
	defer func() {
		panicValue := recover()
		if panicValue == nil {
			t.Fatalf("expected function to panic with %q", expectedPanicString)
		}

		panicString, ok := panicValue.(string)
		if !ok {
			t.Fatalf("expected string panic value, got: %v", panicValue)
		}

		if !strings.Contains(panicString, expectedPanicString) {
			t.Fatalf("received unexpected panic: %q - wanted %q", panicString, expectedPanicString)
		}
	}()

	fn()
}

func TestBitBuffer(t *testing.T) {
	t.Run("popping trailing bits", func(t *testing.T) {
		bb := newBitBuffer(big.NewInt(0b0000_1111_0000_1111_0101), 20)

		actual := bb.PopTrailingBits(4).Uint64()
		expected := uint64(0b0101)
		if actual != expected {
			t.Fatalf("failed to pop trailing bits\nWanted %.4b\nGot    %.4b", expected, actual)
		}

		actual = bb.PopTrailingBits(4).Uint64()
		expected = uint64(0b1111)
		if actual != expected {
			t.Fatalf("failed to pop trailing bits\nWanted %.4b\nGot    %.4b", expected, actual)
		}

		actual = bb.PopTrailingBits(12).Uint64()
		expected = uint64(0b0000_1111_0000)
		if actual != expected {
			t.Fatalf("failed to pop trailing bits\nWanted %.12b\nGot    %.12b", expected, actual)
		}

		shouldPanicWith(t, "attempted to read outside buffer", func() {
			bb.PopTrailingBits(4)
		})
	})

	t.Run("popping leading bits", func(t *testing.T) {
		bb := newBitBuffer(big.NewInt(0b0000_1111_0000_1111_0101), 20)

		actual := bb.PopLeadingBits(4).Uint64()
		expected := uint64(0b0000)
		if actual != expected {
			t.Fatalf("failed to pop leading bits\nWanted %.4b\nGot    %.4b", expected, actual)
		}

		actual = bb.PopLeadingBits(4).Uint64()
		expected = uint64(0b1111)
		if actual != expected {
			t.Fatalf("failed to pop leading bits\nWanted %.4b\nGot    %.4b", expected, actual)
		}

		actual = bb.PopLeadingBits(12).Uint64()
		expected = uint64(0b0000_1111_0101)
		if actual != expected {
			t.Fatalf("failed to pop leading bits\nWanted %.12b\nGot    %.12b", expected, actual)
		}

		shouldPanicWith(t, "attempted to read outside buffer", func() {
			bb.PopLeadingBits(4)
		})
	})

	t.Run("popping leading and trailing bits", func(t *testing.T) {
		bb := newBitBuffer(big.NewInt(0b0001_1001_0110_0101_1001), 20)

		actual := bb.PopLeadingBits(8).Uint64()
		expected := uint64(0b0001_1001)
		if actual != expected {
			t.Fatalf("failed to pop leading bits\nWanted %.8b\nGot    %.8b", expected, actual)
		}

		actual = bb.PopTrailingBits(4).Uint64()
		expected = uint64(0b1001)
		if actual != expected {
			t.Fatalf("failed to pop trailing bits\nWanted %.4b\nGot    %.4b", expected, actual)
		}

		actual = bb.PopLeadingBits(4).Uint64()
		expected = uint64(0b0110)
		if actual != expected {
			t.Fatalf("failed to pop leading bits\nWanted %.4b\nGot    %.4b", expected, actual)
		}

		actual = bb.PopTrailingBits(4).Uint64()
		expected = uint64(0b0101)
		if actual != expected {
			t.Fatalf("failed to pop trailing bits\nWanted %.4b\nGot    %.4b", expected, actual)
		}

		shouldPanicWith(t, "attempted to read outside buffer", func() {
			bb.PopTrailingBits(1)
		})
	})

	t.Run("panics on value too large for specified size", func(t *testing.T) {
		shouldPanicWith(t, "value BitLen 4 is larger than buffer size 3", func() {
			newBitBuffer(big.NewInt(0b1111), 3)
		})
	})

	t.Run("conversion to byte slices", func(t *testing.T) {
		if b := newBitBuffer(big.NewInt(0), 0).Bytes(); len(b) != 0 {
			t.Fatalf("expected empty bitBuffer to return empty byte slice, got %X", b)
		}

		fixtures := []struct {
			Value    uint
			BitSize  uint
			Expected []byte
		}{
			{
				Value:    0,
				BitSize:  8,
				Expected: []byte{0x00},
			},
			{
				Value:    0,
				BitSize:  15,
				Expected: []byte{0x00, 0x00},
			},
			{
				Value:    0x01,
				BitSize:  1,
				Expected: []byte{0x01},
			},
			{
				Value:    0x08,
				BitSize:  4,
				Expected: []byte{0x08},
			},
			{
				Value:    0x121A,
				BitSize:  16,
				Expected: []byte{0x12, 0x1A},
			},
			{
				Value:    0x121A,
				BitSize:  17,
				Expected: []byte{0x00, 0x12, 0x1A},
			},
		}

		for _, fixture := range fixtures {
			actual := newBitBuffer(big.NewInt(int64(fixture.Value)), fixture.BitSize).Bytes()
			if !bytes.Equal(actual, fixture.Expected) {
				t.Errorf("failed to convert bitBuffer to bytes. Wanted %X, got %X", fixture.Expected, actual)
			}
		}
	})
}
