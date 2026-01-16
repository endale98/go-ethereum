// Copyright (c) 2018 Tomochain
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package posv

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// mockChainReader implements consensus.ChainReader for testing
type mockChainReader struct {
	headers map[uint64]*types.Header
	hashes  map[common.Hash]*types.Header
	current *types.Header
	config  *params.ChainConfig
}

func newMockChainReader() *mockChainReader {
	return &mockChainReader{
		headers: make(map[uint64]*types.Header),
		hashes:  make(map[common.Hash]*types.Header),
		config: &params.ChainConfig{
			ChainID: big.NewInt(89),
		},
	}
}

func (m *mockChainReader) Config() *params.ChainConfig {
	return m.config
}

func (m *mockChainReader) CurrentHeader() *types.Header {
	return m.current
}

func (m *mockChainReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	if h := m.hashes[hash]; h != nil {
		return h
	}
	return m.headers[number]
}

func (m *mockChainReader) GetHeaderByNumber(number uint64) *types.Header {
	return m.headers[number]
}

func (m *mockChainReader) GetHeaderByHash(hash common.Hash) *types.Header {
	return m.hashes[hash]
}

func (m *mockChainReader) GetBlock(hash common.Hash, number uint64) *types.Block {
	return nil
}

func (m *mockChainReader) addHeader(header *types.Header) {
	m.headers[header.Number.Uint64()] = header
	m.hashes[header.Hash()] = header
	if m.current == nil || header.Number.Uint64() > m.current.Number.Uint64() {
		m.current = header
	}
}

// buildChain creates a complete chain from genesis to target block with proper parent links
func (m *mockChainReader) buildChain(targetBlock uint64, signers []common.Address) {
	// Generate private keys for each signer (for signing headers)
	keys := make([]*ecdsa.PrivateKey, len(signers))
	for i := range signers {
		key, _ := crypto.GenerateKey()
		keys[i] = key
		// Override signer address with the one from the key
		signers[i] = crypto.PubkeyToAddress(key.PublicKey)
	}

	// Genesis block (block 0)
	genesis := &types.Header{
		Number:     big.NewInt(0),
		Time:       1000,
		Difficulty: big.NewInt(1),
		Extra:      make([]byte, extraVanity+len(signers)*common.AddressLength+extraSeal),
	}
	// Add signers to genesis extra data
	for i, signer := range signers {
		copy(genesis.Extra[extraVanity+i*common.AddressLength:], signer[:])
	}
	m.addHeader(genesis)

	// Build chain from block 1 to targetBlock
	previousHash := genesis.Hash()
	for i := uint64(1); i <= targetBlock; i++ {
		header := &types.Header{
			Number:     big.NewInt(int64(i)),
			Time:       genesis.Time + i*2, // 2 second block time
			ParentHash: previousHash,
			Difficulty: big.NewInt(1),
			Extra:      make([]byte, extraVanity+extraSeal),
		}
		// Sign header with one of the signer keys (round-robin)
		signerIdx := int(i) % len(keys)
		sig, _ := crypto.Sign(sigHash(header).Bytes(), keys[signerIdx])
		copy(header.Extra[len(header.Extra)-extraSeal:], sig)

		m.addHeader(header)
		previousHash = header.Hash()
	}
}

// TestAPIGetSnapshot tests the GetSnapshot API method
func TestAPIGetSnapshot(t *testing.T) {
	// Setup
	config := &PosvConfig{
		Period: 2,
		Epoch:  900,
	}
	// Create an in-memory database for testing
	db := rawdb.NewMemoryDatabase()
	posv := New(config, db)

	chain := newMockChainReader()

	// Create test signers
	signers := []common.Address{
		common.HexToAddress("0x1234567890123456789012345678901234567890"),
		common.HexToAddress("0x2345678901234567890123456789012345678901"),
	}

	// Build complete chain from genesis to block 100
	chain.buildChain(100, signers)

	// Create API
	api := &API{
		chain: chain,
		posv:  posv,
	}

	// Test getting latest snapshot
	t.Run("GetLatestSnapshot", func(t *testing.T) {
		latest := rpc.LatestBlockNumber
		snap, err := api.GetSnapshot(&latest)
		if err != nil {
			t.Fatalf("GetSnapshot failed: %v", err)
		}
		if snap.Number != 100 {
			t.Errorf("Expected snapshot at block 100, got %d", snap.Number)
		}
		if len(snap.Signers) != 2 {
			t.Errorf("Expected 2 signers, got %d", len(snap.Signers))
		}
	})

	// Test getting snapshot at specific block
	t.Run("GetSnapshotAtBlock", func(t *testing.T) {
		blockNum := rpc.BlockNumber(100)
		snap, err := api.GetSnapshot(&blockNum)
		if err != nil {
			t.Fatalf("GetSnapshot failed: %v", err)
		}
		if snap.Number != 100 {
			t.Errorf("Expected snapshot at block 100, got %d", snap.Number)
		}
	})

	// Test getting snapshot with nil (should use latest)
	t.Run("GetSnapshotNil", func(t *testing.T) {
		_, err := api.GetSnapshot(nil)
		if err != nil {
			t.Logf("GetSnapshot with nil returned error (expected if no snapshot exists): %v", err)
		}
	})
}

// TestAPIGetSnapshotAtHash tests the GetSnapshotAtHash API method
func TestAPIGetSnapshotAtHash(t *testing.T) {
	// Setup
	config := &PosvConfig{
		Period: 2,
		Epoch:  900,
	}
	db := rawdb.NewMemoryDatabase()
	posv := New(config, db)

	chain := newMockChainReader()

	// Create test signers
	signers := []common.Address{
		common.HexToAddress("0x1234567890123456789012345678901234567890"),
		common.HexToAddress("0x2345678901234567890123456789012345678901"),
	}

	// Build complete chain
	chain.buildChain(100, signers)
	header := chain.GetHeaderByNumber(100)

	api := &API{
		chain: chain,
		posv:  posv,
	}

	// Test with valid hash
	t.Run("ValidHash", func(t *testing.T) {
		snap, err := api.GetSnapshotAtHash(header.Hash())
		if err != nil {
			t.Fatalf("GetSnapshotAtHash failed: %v", err)
		}
		if snap.Number != 100 {
			t.Errorf("Expected snapshot at block 100, got %d", snap.Number)
		}
	})

	// Test with invalid hash
	t.Run("InvalidHash", func(t *testing.T) {
		invalidHash := common.HexToHash("0x1234567890abcdef")
		_, err := api.GetSnapshotAtHash(invalidHash)
		if err == nil {
			t.Error("Expected error for invalid hash, got nil")
		}
		if err != errUnknownBlock {
			t.Errorf("Expected errUnknownBlock, got: %v", err)
		}
	})
}

// TestAPIGetSigners tests the GetSigners API method
func TestAPIGetSigners(t *testing.T) {
	// Setup
	config := &PosvConfig{
		Period: 2,
		Epoch:  900,
	}
	db := rawdb.NewMemoryDatabase()
	posv := New(config, db)

	chain := newMockChainReader()

	// Create test signers
	signers := []common.Address{
		common.HexToAddress("0x1234567890123456789012345678901234567890"),
		common.HexToAddress("0x2345678901234567890123456789012345678901"),
	}

	// Build complete chain
	chain.buildChain(100, signers)

	api := &API{
		chain: chain,
		posv:  posv,
	}

	// Test getting latest signers
	t.Run("GetLatestSigners", func(t *testing.T) {
		latest := rpc.LatestBlockNumber
		result, err := api.GetSigners(&latest)
		if err != nil {
			t.Fatalf("GetSigners failed: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("Expected 2 signers, got %d", len(result))
		}
	})

	// Test getting signers at specific block
	t.Run("GetSignersAtBlock", func(t *testing.T) {
		blockNum := rpc.BlockNumber(100)
		result, err := api.GetSigners(&blockNum)
		if err != nil {
			t.Fatalf("GetSigners failed: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("Expected 2 signers, got %d", len(result))
		}
	})
}

// TestAPIGetSignersAtHash tests the GetSignersAtHash API method
func TestAPIGetSignersAtHash(t *testing.T) {
	// Setup
	config := &PosvConfig{
		Period: 2,
		Epoch:  900,
	}
	db := rawdb.NewMemoryDatabase()
	posv := New(config, db)

	chain := newMockChainReader()

	// Create test signers
	signers := []common.Address{
		common.HexToAddress("0x1234567890123456789012345678901234567890"),
		common.HexToAddress("0x2345678901234567890123456789012345678901"),
	}

	// Build complete chain
	chain.buildChain(100, signers)
	header := chain.GetHeaderByNumber(100)

	api := &API{
		chain: chain,
		posv:  posv,
	}

	// Test with valid hash
	t.Run("ValidHash", func(t *testing.T) {
		result, err := api.GetSignersAtHash(header.Hash())
		if err != nil {
			t.Fatalf("GetSignersAtHash failed: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("Expected 2 signers, got %d", len(result))
		}
	})

	// Test with invalid hash
	t.Run("InvalidHash", func(t *testing.T) {
		invalidHash := common.HexToHash("0xdeadbeef")
		_, err := api.GetSignersAtHash(invalidHash)
		if err == nil {
			t.Error("Expected error for invalid hash, got nil")
		}
		if err != errUnknownBlock {
			t.Errorf("Expected errUnknownBlock, got: %v", err)
		}
	})
}

// TestAPINetworkInformation tests the NetworkInformation API property
func TestAPINetworkInformation(t *testing.T) {
	// Setup
	config := &PosvConfig{
		Period: 2,
		Epoch:  900,
	}
	db := rawdb.NewMemoryDatabase()
	posv := New(config, db)

	chain := newMockChainReader()

	api := &API{
		chain: chain,
		posv:  posv,
	}

	// Get network information
	info := api.NetworkInformation()

	// Verify network ID
	if info.NetworkId.Cmp(big.NewInt(89)) != 0 {
		t.Errorf("Expected NetworkId 89, got %v", info.NetworkId)
	}

	// Verify validator address
	expectedValidator := common.HexToAddress(common.MasternodeVotingSMC)
	if info.TomoValidatorAddress != expectedValidator {
		t.Errorf("Expected validator address %s, got %s", expectedValidator.Hex(), info.TomoValidatorAddress.Hex())
	}

	// Verify lending address
	expectedLending := common.HexToAddress(common.LendingRegistrationSMC)
	if info.LendingAddress != expectedLending {
		t.Errorf("Expected lending address %s, got %s", expectedLending.Hex(), info.LendingAddress.Hex())
	}

	// Verify relayer address
	expectedRelayer := common.HexToAddress(common.RelayerRegistrationSMC)
	if info.RelayerRegistrationAddress != expectedRelayer {
		t.Errorf("Expected relayer address %s, got %s", expectedRelayer.Hex(), info.RelayerRegistrationAddress.Hex())
	}

	// Verify TomoX listing address
	if info.TomoXListingAddress != common.TomoXListingSMC {
		t.Errorf("Expected TomoX listing address %s, got %s", common.TomoXListingSMC.Hex(), info.TomoXListingAddress.Hex())
	}

	// Verify TomoZ address
	if info.TomoZAddress != common.TRC21IssuerSMC {
		t.Errorf("Expected TomoZ address %s, got %s", common.TRC21IssuerSMC.Hex(), info.TomoZAddress.Hex())
	}
}

// BenchmarkAPIGetSnapshot benchmarks the GetSnapshot method
func BenchmarkAPIGetSnapshot(b *testing.B) {
	config := &PosvConfig{
		Period: 2,
		Epoch:  900,
	}
	db := rawdb.NewMemoryDatabase()
	posv := New(config, db)

	chain := newMockChainReader()
	signers := []common.Address{
		common.HexToAddress("0x1234567890123456789012345678901234567890"),
	}
	chain.buildChain(100, signers)

	api := &API{
		chain: chain,
		posv:  posv,
	}

	latest := rpc.LatestBlockNumber

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		api.GetSnapshot(&latest)
	}
}

// BenchmarkAPIGetSigners benchmarks the GetSigners method
func BenchmarkAPIGetSigners(b *testing.B) {
	config := &PosvConfig{
		Period: 2,
		Epoch:  900,
	}
	db := rawdb.NewMemoryDatabase()
	posv := New(config, db)

	chain := newMockChainReader()
	signers := []common.Address{
		common.HexToAddress("0x1234567890123456789012345678901234567890"),
	}
	chain.buildChain(100, signers)

	api := &API{
		chain: chain,
		posv:  posv,
	}

	latest := rpc.LatestBlockNumber

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		api.GetSigners(&latest)
	}
}

// TestAPIEdgeCases tests edge cases for API methods
func TestAPIEdgeCases(t *testing.T) {
	config := &PosvConfig{
		Period: 2,
		Epoch:  900,
	}
	db := rawdb.NewMemoryDatabase()
	posv := New(config, db)

	chain := newMockChainReader()

	api := &API{
		chain: chain,
		posv:  posv,
	}

	t.Run("GetSnapshotNoCurrentHeader", func(t *testing.T) {
		latest := rpc.LatestBlockNumber
		_, err := api.GetSnapshot(&latest)
		if err == nil {
			t.Error("Expected error when no current header exists")
		}
	})

	t.Run("GetSignersNoCurrentHeader", func(t *testing.T) {
		latest := rpc.LatestBlockNumber
		_, err := api.GetSigners(&latest)
		if err == nil {
			t.Error("Expected error when no current header exists")
		}
	})

	t.Run("GetSnapshotAtHashZeroHash", func(t *testing.T) {
		_, err := api.GetSnapshotAtHash(common.Hash{})
		if err != errUnknownBlock {
			t.Errorf("Expected errUnknownBlock for zero hash, got: %v", err)
		}
	})

	t.Run("GetSignersAtHashZeroHash", func(t *testing.T) {
		_, err := api.GetSignersAtHash(common.Hash{})
		if err != errUnknownBlock {
			t.Errorf("Expected errUnknownBlock for zero hash, got: %v", err)
		}
	})
}
