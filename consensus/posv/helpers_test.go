package posv

import (
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

type BlockJSON struct {
	ParentHash  common.Hash      `json:"parentHash"`
	UncleHash   common.Hash      `json:"sha3Uncles"`       // Map: sha3Uncles -> UncleHash
	Coinbase    common.Address   `json:"miner"`            // Map: miner -> Coinbase
	Root        common.Hash      `json:"stateRoot"`        // Map: stateRoot -> Root
	TxHash      common.Hash      `json:"transactionsRoot"` // Map: transactionsRoot -> TxHash
	ReceiptHash common.Hash      `json:"receiptsRoot"`     // Map: receiptsRoot -> ReceiptHash
	Bloom       types.Bloom      `json:"logsBloom"`
	Difficulty  *hexutil.Big     `json:"difficulty"` //  parse "0x..." -> big.Int
	Number      *hexutil.Big     `json:"number"`
	GasLimit    hexutil.Uint64   `json:"gasLimit"` //  parse "0x..." -> uint64
	GasUsed     hexutil.Uint64   `json:"gasUsed"`
	Time        hexutil.Uint64   `json:"timestamp"` // Map: timestamp -> Time
	Extra       hexutil.Bytes    `json:"extraData"` //  parse "0x..." -> []byte
	MixDigest   common.Hash      `json:"mixHash"`
	Nonce       types.BlockNonce `json:"nonce"`
	LegacyHash  common.Hash      `json:"hash"`
}

// MockChain implements consensus.ChainHeaderReader and ChainReader
type MockChain struct {
	headers map[common.Hash]*types.Header
	config  *params.ChainConfig
	engine  *Posv
}

var _ consensus.ChainHeaderReader = &MockChain{}

func NewMockChain(config *params.ChainConfig) *MockChain {
	return &MockChain{
		headers: make(map[common.Hash]*types.Header),
		config:  config,
	}
}

func (m *MockChain) Config() *params.ChainConfig {
	return m.config
}

func (m *MockChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	return m.headers[hash]
}

func (m *MockChain) GetHeaderByNumber(number uint64) *types.Header {
	for _, h := range m.headers {
		if h.Number.Uint64() == number {
			return h
		}
	}
	return nil
}

func (m *MockChain) GetHeaderByHash(hash common.Hash) *types.Header {
	return m.headers[hash]
}

func (m *MockChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	header := m.GetHeader(hash, number)
	if header == nil {
		return nil
	}
	return types.NewBlockWithHeader(header)
}

// CurrentHeader is needed for ChainReader but we can return nil or latest
func (m *MockChain) CurrentHeader() *types.Header {
	var latest *types.Header
	for _, h := range m.headers {
		if latest == nil || h.Number.Cmp(latest.Number) > 0 {
			latest = h
		}
	}
	return latest
}

// PutHeader stores the header in the mock chain
func (m *MockChain) PutHeader(header *types.Header) {
	m.headers[header.Hash()] = header
}

// Helper: Generate a mock key and address
func GenerateMockKey(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	return key, addr
}

func (m *MockChain) AddHeader(h *types.Header) {
	m.headers[h.Hash()] = h
}

func MockGenesis(t *testing.T) *MockChain {
	// Load genesis.json to get configuration
	genesisData, err := os.ReadFile("../../cmd/dev/testdata/genesis.json")
	if err != nil {
		t.Fatalf("Failed to read genesis.json: %v", err)
	}

	var genesis core.Genesis
	if err := json.Unmarshal(genesisData, &genesis); err != nil {
		t.Fatalf("Failed to unmarshal genesis.json: %v", err)
	}

	config := genesis.Config
	posvConfig := &PosvConfig{
		Period:              config.Posv.Period,
		Epoch:               config.Posv.Epoch,
		Reward:              config.Posv.Reward,
		RewardCheckpoint:    config.Posv.RewardCheckpoint,
		Gap:                 config.Posv.Gap,
		FoudationWalletAddr: config.Posv.FoudationWalletAddr,
	}

	db := rawdb.NewMemoryDatabase()
	// Initialize engine
	engine := New(posvConfig, db)

	// Create a MockKey for signing
	key, _ := crypto.GenerateKey()
	mockAddress := crypto.PubkeyToAddress(key.PublicKey)
	t.Logf("Mock Validator Address: %s\n", mockAddress.Hex())

	// Set the signer in the engine (locks required if parallel, but this is single threaded)
	engine.signer = mockAddress
	engine.signFn = func(a accounts.Account, n []byte) ([]byte, error) {
		return crypto.Sign(n, key)
	}

	// Mock Chain Reader
	chain := NewMockChain(config)
	// Convert core.Genesis to Block
	genesisBlock := genesis.ToBlock()
	genesisHeader := genesisBlock.Header()
	t.Logf("Loaded genesis header hash %s\n", genesisHeader.Hash().Hex())

	// Store Genesis
	chain.PutHeader(genesisHeader)

	// Create and store initial snapshot for blocks working on top of Genesis
	genesisSigners := []common.Address{mockAddress}
	// Create a snapshot at block 0
	snap := newSnapshot(posvConfig, engine.signatures, 0, genesisHeader.Hash(), genesisSigners)
	engine.recents.Add(genesisHeader.Hash(), snap)

	chain.engine = engine

	head := chain.CurrentHeader()
	t.Logf("Mock chain genesis header number: %d\n", head.Number.Uint64())
	t.Logf("hash %v\n", head.Hash().Hex())

	t.Logf("Genesis hash %s\n", genesisHeader.Hash().Hex())

	return chain
}
