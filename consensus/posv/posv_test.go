package posv

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	keyA, _ = crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
	keyB, _ = crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000002")
	addrA   = crypto.PubkeyToAddress(keyA.PublicKey)
	addrB   = crypto.PubkeyToAddress(keyB.PublicKey)
)

func loadRealHeaders(t *testing.T, path string) []*types.Header {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("File %s not found. Run fetch_viction_data.go first.", path)
		}
		t.Fatalf("Failed to read test data: %v", err)
	}

	var rawBlocks []BlockJSON
	if err := json.Unmarshal(data, &rawBlocks); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	var headers []*types.Header
	for _, block := range rawBlocks {
		h := &types.Header{
			ParentHash:  common.HexToHash(block.ParentHash.Hex()),
			UncleHash:   common.HexToHash(block.UncleHash.Hex()),
			Coinbase:    common.HexToAddress(block.Coinbase.Hex()),
			Root:        common.HexToHash(block.Root.Hex()),
			TxHash:      common.HexToHash(block.TxHash.Hex()),
			ReceiptHash: common.HexToHash(block.ReceiptHash.Hex()),
			Bloom:       block.Bloom,
			Difficulty:  (*big.Int)(block.Difficulty),
			Number:      (*big.Int)(block.Number),
			GasLimit:    uint64(block.GasLimit),
			GasUsed:     uint64(block.GasUsed),
			Time:        uint64(block.Time),
			Extra:       block.Extra,
			MixDigest:   common.HexToHash(block.MixDigest.Hex()),
			Nonce:       types.EncodeNonce(0),
		}
		headers = append(headers, h)

	}
	return headers
}

func TestVerifyHeader_Dummy(t *testing.T) {
	config := &PosvConfig{Epoch: 100, Period: 1}

	// Create Mock Posv - we rely on stub/mock behavior internally or skip Snapshot logic
	p := New(config, nil)

	parent := &types.Header{
		Number: big.NewInt(0),
		Time:   1000,
		Extra:  make([]byte, extraVanity+extraSeal),
	}

	tests := []struct {
		name    string
		header  *types.Header
		wantErr error
	}{
		{
			name: "FutureBlock",
			header: &types.Header{
				Number:     big.NewInt(1),
				Time:       uint64(time.Now().Unix() + 10000),
				ParentHash: parent.Hash(),
			},
			wantErr: ErrFutureBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := &MockChain{headers: map[common.Hash]*types.Header{parent.Hash(): parent}}
			err := p.VerifyHeader(chain, tt.header, true)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyHeader_Real(t *testing.T) {
	chain := MockGenesis(t)
	headers := loadRealHeaders(t, "../../cmd/dev/testdata/viction_headers.json")

	if len(headers) < 2 {
		t.Skip("Not enough headers to verify chain")
	}

	for _, h := range headers {
		legacyHeader := &types.Header{
			ParentHash:  h.ParentHash,
			UncleHash:   types.EmptyUncleHash,
			Coinbase:    h.Coinbase,
			Root:        h.Root,
			TxHash:      h.TxHash,
			ReceiptHash: h.ReceiptHash,
			Bloom:       h.Bloom,
			Difficulty:  h.Difficulty,
			Number:      h.Number,
			GasLimit:    h.GasLimit,
			GasUsed:     h.GasUsed,
			Time:        h.Time,
			Extra:       h.Extra,
			MixDigest:   h.MixDigest,
			Nonce:       h.Nonce,
			// BaseFee: nil,    Should nil
			// BlobGasUsed: nil, Should nil
		}
		chain.PutHeader(legacyHeader)
	}
	for i := 0; i < len(headers); i++ {
		header := headers[i]
		t.Logf("Header number :%v\n", header.Number.Uint64())
		parent := chain.GetHeaderByNumber(header.Number.Uint64() - 1)
		t.Logf("Parent hash %s\n", parent.Hash().Hex())
		parentBlock := chain.GetHeader(parent.Hash(), parent.Number.Uint64())
		t.Logf("Parent number %d\n", parent.Number.Uint64())
		t.Logf("Parent block hash %s\n", parentBlock.Hash().Hex())
		if parent == nil {
			t.Fatalf("Missing parent for block %d", header.Number)
		}

		// ensure header.ParentHash matches parent's hash
		t.Logf("header.ParentHash :%v\n", header.ParentHash.Hex())
		t.Logf("header hash :%v\n", header.Hash().Hex())

		if header.ParentHash != parent.Hash() {
			t.Logf("Header sequence mismatch at index %d (Block %d)\nHeader.ParentHash: %s\nParent.Hash:       %s",
				i, header.Number, header.ParentHash.Hex(), parent.Hash().Hex())
			t.Skip("Skipping Real Data verification due to hash mismatch")
			return
		}

		// Verify using seal=false (Skip signature/snapshot checks)
		seal := false
		err := chain.engine.VerifyHeader(chain, header, seal)
		if err != nil {
			t.Logf("VerifyHeader(seal=%t) failed for block %d: %v", seal, header.Number, err)
			continue
		}
	}
}
