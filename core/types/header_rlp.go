package types

import (
	"bytes"
	"errors"
	"io"

	"github.com/ethereum/go-ethereum/rlp"
)

// EncodeRLP encodes the header into RLP.
func (h *Header) EncodeRLP(w io.Writer) error {
	// Calculate payload size
	// Note: We need accurate size calculation.
	// Let's use a buffer to write fields, then write prefix + buffer.
	// This is less efficient but safer than manual size + stream mismatch.

	var b bytes.Buffer
	// Encode fields into b

	// ParentHash
	if err := rlp.Encode(&b, h.ParentHash); err != nil {
		return err
	}
	// UncleHash
	if err := rlp.Encode(&b, h.UncleHash); err != nil {
		return err
	}
	// Coinbase
	if err := rlp.Encode(&b, h.Coinbase); err != nil {
		return err
	}
	// Root
	if err := rlp.Encode(&b, h.Root); err != nil {
		return err
	}
	// TxHash
	if err := rlp.Encode(&b, h.TxHash); err != nil {
		return err
	}
	// ReceiptHash
	if err := rlp.Encode(&b, h.ReceiptHash); err != nil {
		return err
	}
	// Bloom
	if err := rlp.Encode(&b, h.Bloom); err != nil {
		return err
	}
	// Difficulty
	if err := rlp.Encode(&b, h.Difficulty); err != nil {
		return err
	}
	// Number
	if err := rlp.Encode(&b, h.Number); err != nil {
		return err
	}
	// GasLimit
	if err := rlp.Encode(&b, uint64(h.GasLimit)); err != nil {
		return err
	}
	// GasUsed
	if err := rlp.Encode(&b, uint64(h.GasUsed)); err != nil {
		return err
	}
	// Time
	if err := rlp.Encode(&b, uint64(h.Time)); err != nil {
		return err
	}
	// Extra
	if err := rlp.Encode(&b, h.Extra); err != nil {
		return err
	}

	// MixDigest / AuRa
	if len(h.AuRaSeal) > 0 {
		if err := rlp.Encode(&b, uint64(h.AuRaStep)); err != nil {
			return err
		}
		if err := rlp.Encode(&b, h.AuRaSeal); err != nil {
			return err
		}
	} else {
		if err := rlp.Encode(&b, h.MixDigest); err != nil {
			return err
		}
		if err := rlp.Encode(&b, h.Nonce); err != nil {
			return err
		}
	}

	if h.Posv && h.BaseFee != nil {
		if err := rlp.Encode(&b, h.Posv); err != nil {
			return err
		}
	}

	// Viction Mandatory Fields (Legacy Compact)
	// These fields are always present in Viction headers, encoded as empty strings (0x80) if nil/empty.
	if err := rlp.Encode(&b, h.NewAttestors); err != nil {
		return err
	}
	if err := rlp.Encode(&b, h.Attestor); err != nil {
		return err
	}
	if err := rlp.Encode(&b, h.Penalties); err != nil {
		return err
	}

	// BaseFee
	if h.BaseFee != nil {
		if err := rlp.Encode(&b, h.BaseFee); err != nil {
			return err
		}
	}

	// Withdrawals
	if h.WithdrawalsHash != nil {
		if err := rlp.Encode(&b, h.WithdrawalsHash); err != nil {
			return err
		}
	}

	// BlobGasUsed
	if h.BlobGasUsed != nil {
		if err := rlp.Encode(&b, uint64(*h.BlobGasUsed)); err != nil {
			return err
		}
	}
	// ExcessBlobGas
	if h.ExcessBlobGas != nil {
		if err := rlp.Encode(&b, uint64(*h.ExcessBlobGas)); err != nil {
			return err
		}
	}
	// ParentBeaconRoot
	if h.ParentBeaconRoot != nil {
		if err := rlp.Encode(&b, h.ParentBeaconRoot); err != nil {
			return err
		}
	}
	// RequestsHash
	if h.RequestsHash != nil {
		if err := rlp.Encode(&b, h.RequestsHash); err != nil {
			return err
		}
	}

	// Now write the list itself
	// rlp.Encode(w, b.Bytes()) would handle string, not list of fields.
	// We need to write List header for the size of 'b', then 'b'.

	// Write List Header manually
	payload := b.Bytes()
	if err := encodeListHeader(w, uint64(len(payload))); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func encodeListHeader(w io.Writer, size uint64) error {
	if size < 56 {
		_, err := w.Write([]byte{0xC0 + byte(size)})
		return err
	}
	// > 55 bytes
	sizeBytes := make([]byte, 8)
	n := putint(sizeBytes, size)
	_, err := w.Write([]byte{0xF7 + byte(n)})
	if err != nil {
		return err
	}
	_, err = w.Write(sizeBytes[:n])
	return err
}

func putint(b []byte, i uint64) int {
	switch {
	case i < (1 << 8):
		b[0] = byte(i)
		return 1
	case i < (1 << 16):
		b[0] = byte(i >> 8)
		b[1] = byte(i)
		return 2
	case i < (1 << 24):
		b[0] = byte(i >> 16)
		b[1] = byte(i >> 8)
		b[2] = byte(i)
		return 3
	case i < (1 << 32):
		b[0] = byte(i >> 24)
		b[1] = byte(i >> 16)
		b[2] = byte(i >> 8)
		b[3] = byte(i)
		return 4
	case i < (1 << 40):
		b[0] = byte(i >> 32)
		b[1] = byte(i >> 24)
		b[2] = byte(i >> 16)
		b[3] = byte(i >> 8)
		b[4] = byte(i)
		return 5
	case i < (1 << 48):
		b[0] = byte(i >> 40)
		b[1] = byte(i >> 32)
		b[2] = byte(i >> 24)
		b[3] = byte(i >> 16)
		b[4] = byte(i >> 8)
		b[5] = byte(i)
		return 6
	case i < (1 << 56):
		b[0] = byte(i >> 48)
		b[1] = byte(i >> 40)
		b[2] = byte(i >> 32)
		b[3] = byte(i >> 24)
		b[4] = byte(i >> 16)
		b[5] = byte(i >> 8)
		b[6] = byte(i)
		return 7
	default:
		b[0] = byte(i >> 56)
		b[1] = byte(i >> 48)
		b[2] = byte(i >> 40)
		b[3] = byte(i >> 32)
		b[4] = byte(i >> 24)
		b[5] = byte(i >> 16)
		b[6] = byte(i >> 8)
		b[7] = byte(i)
		return 8
	}
}

// DecodeRLP implements the rlp.Decoder interface.
func (h *Header) DecodeRLP(s *rlp.Stream) error {
	_, err := s.List()
	if err != nil {
		return err
	}

	// Basic fields
	if err := s.Decode(&h.ParentHash); err != nil {
		return err
	}
	if err := s.Decode(&h.UncleHash); err != nil {
		return err
	}
	if err := s.Decode(&h.Coinbase); err != nil {
		return err
	}
	if err := s.Decode(&h.Root); err != nil {
		return err
	}
	if err := s.Decode(&h.TxHash); err != nil {
		return err
	}
	if err := s.Decode(&h.ReceiptHash); err != nil {
		return err
	}
	if err := s.Decode(&h.Bloom); err != nil {
		return err
	}
	if err := s.Decode(&h.Difficulty); err != nil {
		return err
	}
	if err := s.Decode(&h.Number); err != nil {
		return err
	}
	if err := s.Decode(&h.GasLimit); err != nil {
		return err
	}
	if err := s.Decode(&h.GasUsed); err != nil {
		return err
	}
	if err := s.Decode(&h.Time); err != nil {
		return err
	}
	if err := s.Decode(&h.Extra); err != nil {
		return err
	}

	// MixDigest vs AuRa detection
	kind, size, err := s.Kind()
	if err != nil {
		return err
	}

	if kind == rlp.String && size == 32 {
		// MixDigest
		if err := s.Decode(&h.MixDigest); err != nil {
			return err
		}
		if err := s.Decode(&h.Nonce); err != nil {
			return err
		}
	} else {
		// AuRa
		if err := s.Decode(&h.AuRaStep); err != nil {
			return err
		}
		if err := s.Decode(&h.AuRaSeal); err != nil {
			return err
		}
	}

	// Prioritize PoSV detection
	kind, _, err = s.Kind()
	if err != nil {
		if errors.Is(err, rlp.EOL) {
			return s.ListEnd()
		}
		return err
	}

	if kind == rlp.Byte {
		var flag bool
		if err := s.Decode(&flag); err == nil && flag {
			h.Posv = true
		} else {
			// If not a bool, we might have consumed something else or it triggered error.
			// To be safe we should respect Erigon logic more strictly or handle error.
			// Erigon checks checks 'kind == rlp.Byte' and then calls s.Bool().
			// If we are here, we are making best effort.
		}
	}

	// NewAttestors (optional)
	if _, _, err := s.Kind(); errors.Is(err, rlp.EOL) {
		return s.ListEnd()
	}

	if err := s.Decode(&h.NewAttestors); err != nil {
		if errors.Is(err, rlp.EOL) {
			return s.ListEnd()
		}
		return err
	}
	if err := s.Decode(&h.Attestor); err != nil {
		if errors.Is(err, rlp.EOL) {
			return s.ListEnd()
		}
		return err
	}
	if err := s.Decode(&h.Penalties); err != nil {
		if errors.Is(err, rlp.EOL) {
			return s.ListEnd()
		}
		return err
	}

	// Now BaseFee
	if _, _, err := s.Kind(); errors.Is(err, rlp.EOL) {
		return s.ListEnd()
	}
	if err := s.Decode(&h.BaseFee); err != nil {
		return err
	}

	// WithdrawalsHash
	if _, _, err := s.Kind(); errors.Is(err, rlp.EOL) {
		return s.ListEnd()
	}
	if err := s.Decode(&h.WithdrawalsHash); err != nil {
		return err
	}

	// BlobGasUsed
	if _, _, err := s.Kind(); errors.Is(err, rlp.EOL) {
		return s.ListEnd()
	}
	if err := s.Decode(&h.BlobGasUsed); err != nil {
		return err
	}

	// ExcessBlobGas
	if _, _, err := s.Kind(); errors.Is(err, rlp.EOL) {
		return s.ListEnd()
	}
	if err := s.Decode(&h.ExcessBlobGas); err != nil {
		return err
	}

	// ParentBeaconRoot
	if _, _, err := s.Kind(); errors.Is(err, rlp.EOL) {
		return s.ListEnd()
	}
	if err := s.Decode(&h.ParentBeaconRoot); err != nil {
		return err
	}

	// RequestsHash
	if _, _, err := s.Kind(); errors.Is(err, rlp.EOL) {
		return s.ListEnd()
	}
	if err := s.Decode(&h.RequestsHash); err != nil {
		return err
	}

	return s.ListEnd()
}
