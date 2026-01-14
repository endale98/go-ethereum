package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/crypto/sha3"
)

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// sigHash calculates the signing hash for a block header (simplified version)
func sigHash(header *BlockHeader) common.Hash {
	hasher := sha3.NewLegacyKeccak256()

	// Decode hex fields
	parentHash := common.HexToHash(header.ParentHash)
	uncleHash := common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")
	coinbase := common.HexToAddress(header.Coinbase)

	// Parse block number
	blockNum, _ := strconv.ParseUint(header.Number[2:], 16, 64)

	// Decode extra data and remove signature (last 65 bytes)
	extraBytes, _ := hexutil.Decode(header.Extra)
	if len(extraBytes) < 65 {
		return common.Hash{}
	}
	extraWithoutSig := extraBytes[:len(extraBytes)-65]

	// Decode validator if present
	var validatorBytes []byte
	if header.Validator != "" {
		validatorBytes, _ = hexutil.Decode(header.Validator)
	}

	// Simplified RLP encoding (you may need to adjust based on actual block structure)
	rlp.Encode(hasher, []interface{}{
		parentHash,
		uncleHash,
		coinbase,
		common.Hash{}, // Root
		common.Hash{}, // TxHash
		common.Hash{}, // ReceiptHash
		[256]byte{},   // Bloom
		uint64(1),     // Difficulty
		blockNum,
		uint64(0), // GasLimit
		uint64(0), // GasUsed
		uint64(0), // Time
		extraWithoutSig,
		common.Hash{}, // MixDigest
		[8]byte{},     // Nonce
		validatorBytes,
	})

	var hash common.Hash
	hasher.Sum(hash[:0])
	return hash
}

// recoverSigner recovers the creator/signer address from the Extra field signature
func recoverSigner(header *BlockHeader) (string, error) {
	// Decode extra data
	extraBytes, err := hexutil.Decode(header.Extra)
	if err != nil {
		return "", fmt.Errorf("failed to decode extra: %v", err)
	}

	if len(extraBytes) < 65 {
		return "", fmt.Errorf("extra data too short for signature: %d bytes", len(extraBytes))
	}

	// Get signature from last 65 bytes of extra data (creator signature)
	signature := extraBytes[len(extraBytes)-65:]

	// Calculate signing hash
	hash := sigHash(header)

	// Recover public key
	pubkey, err := crypto.Ecrecover(hash.Bytes(), signature)
	if err != nil {
		return "", fmt.Errorf("ecrecover failed: %v", err)
	}

	// Convert to address
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	return signer.Hex(), nil
}

// recoverValidator recovers the validator address from the Validator field signature
// PoSV uses double validation: creator signs in Extra, validator signs in Validator field
func recoverValidator(header *BlockHeader) (string, error) {
	// Decode validator signature
	validatorBytes, err := hexutil.Decode(header.Validator)
	if err != nil {
		return "", fmt.Errorf("failed to decode validator: %v", err)
	}

	if len(validatorBytes) != 65 {
		return "", fmt.Errorf("validator signature must be 65 bytes, got %d", len(validatorBytes))
	}

	// Calculate signing hash (same as creator)
	hash := sigHash(header)

	// Recover public key from validator signature
	pubkey, err := crypto.Ecrecover(hash.Bytes(), validatorBytes)
	if err != nil {
		return "", fmt.Errorf("ecrecover validator failed: %v", err)
	}

	// Convert to address
	var validator common.Address
	copy(validator[:], crypto.Keccak256(pubkey[1:])[12:])

	return validator.Hex(), nil
}

// BlockHeader represents the block header structure
type BlockHeader struct {
	Number     string `json:"number"`
	Hash       string `json:"hash"`
	ParentHash string `json:"parentHash"`
	Coinbase   string `json:"miner"`
	Extra      string `json:"extraData"`
	Validator  string `json:"validator,omitempty"`
	Penalties  string `json:"penalties,omitempty"`
	Validators string `json:"validators,omitempty"`
}

// SnapshotData represents the complete snapshot structure for testing
type SnapshotData struct {
	Number  uint64                 `json:"number"`
	Hash    string                 `json:"hash"`
	Signers []string               `json:"signers"`
	Recents map[string]string      `json:"recents"`
	Votes   []interface{}          `json:"votes"`
	Tally   map[string]interface{} `json:"tally"`
	Config  map[string]interface{} `json:"config"`
}

func main() {
	// Parse command line flags
	rpcURL := flag.String("rpc", "https://rpc.viction.xyz", "RPC endpoint URL")
	blockNum := flag.Uint64("block", 900, "Block number to dump snapshot from")
	output := flag.String("output", "", "Output file (default: snapshot_block_<number>.json)")
	flag.Parse()

	// Set default output filename
	outputFile := *output
	if outputFile == "" {
		outputFile = fmt.Sprintf("snapshot_block_%d.json", *blockNum)
	}

	fmt.Printf("Connecting to %s...\n", *rpcURL)

	// Connect to RPC
	client, err := rpc.Dial(*rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to RPC: %v", err)
	}
	defer client.Close()

	fmt.Printf("Fetching snapshot data at block %d...\n", *blockNum)
	fmt.Println("Note: Reconstructing snapshot from block headers (public RPC limitation)")

	// Get the target block header
	var header BlockHeader
	blockHex := fmt.Sprintf("0x%x", *blockNum)
	err = client.Call(&header, "eth_getBlockByNumber", blockHex, false)
	if err != nil {
		log.Fatalf("Failed to get block header: %v", err)
	}

	// Log header details
	fmt.Printf("\n=== Block Header ===\n")
	fmt.Printf("Number:     %s (decimal: %d)\n", header.Number, *blockNum)
	fmt.Printf("Hash:       %s\n", header.Hash)
	fmt.Printf("ParentHash: %s\n", header.ParentHash)
	fmt.Printf("Coinbase:   %s\n", header.Coinbase)
	fmt.Printf("Extra:      %s (length: %d)\n", header.Extra, len(header.Extra))
	if header.Validator != "" {
		fmt.Printf("Validator:  %s\n", header.Validator)
	}
	if header.Penalties != "" {
		fmt.Printf("Penalties:  %s\n", header.Penalties)
	}
	if header.Validators != "" {
		fmt.Printf("Validators: %s\n", header.Validators)
	}
	fmt.Printf("==================\n")

	// Parse block number
	blockNumber, _ := strconv.ParseUint(header.Number[2:], 16, 64)

	// Find the most recent checkpoint block
	epoch := uint64(900)
	checkpointBlock := (blockNumber / epoch) * epoch

	fmt.Printf("\nFinding checkpoint at block %d...\n", checkpointBlock)

	// Get checkpoint block to extract signers
	var checkpoint BlockHeader
	checkpointHex := fmt.Sprintf("0x%x", checkpointBlock)
	err = client.Call(&checkpoint, "eth_getBlockByNumber", checkpointHex, false)
	if err != nil {
		log.Fatalf("Failed to get checkpoint block: %v", err)
	}

	// Extract signers from checkpoint
	var signers []string
	if checkpoint.Extra != "" {
		extraBytes, _ := hexutil.Decode(checkpoint.Extra)

		fmt.Printf("\n=== Extra Data Analysis ===\n")
		fmt.Printf("Total Extra field length: %d bytes\n", len(extraBytes))
		fmt.Printf("Extra (first 100 chars): %s...\n", checkpoint.Extra[:min(100, len(checkpoint.Extra))])

		if len(extraBytes) > 97 {
			vanity := 32
			seal := 65
			signersData := extraBytes[vanity : len(extraBytes)-seal]

			fmt.Printf("\n=== Structure Breakdown ===\n")
			fmt.Printf("Vanity (0-31):        %d bytes -> %x\n", vanity, extraBytes[:vanity])
			fmt.Printf("Signers (%d-%d):  %d bytes\n", vanity, len(extraBytes)-seal, len(signersData))
			fmt.Printf("Seal (%d-%d):      %d bytes\n", len(extraBytes)-seal, len(extraBytes), seal)
			fmt.Printf("Total:                %d bytes\n", len(extraBytes))

			// Calculate number of addresses
			numAddresses := len(signersData) / 20
			remainder := len(signersData) % 20

			fmt.Printf("\n=== Signer Calculation ===\n")
			fmt.Printf("Signers section: %d bytes\n", len(signersData))
			fmt.Printf("Address size: 20 bytes\n")
			fmt.Printf("Addresses: %d bytes ÷ 20 = %d addresses", len(signersData), numAddresses)
			if remainder > 0 {
				fmt.Printf(" + %d extra bytes (⚠️  NOT divisible!)\n", remainder)
			} else {
				fmt.Printf(" (exact fit ✓)\n")
			}

			// Extract all addresses regardless of remainder
			fmt.Printf("\n=== Extracted Addresses ===\n")
			for i := 0; i < numAddresses; i++ {
				start := i * 20
				end := start + 20
				if end <= len(signersData) {
					addr := signersData[start:end]
					addrHex := fmt.Sprintf("0x%x", addr)
					signers = append(signers, addrHex)
					fmt.Printf("  %2d: %s\n", i+1, addrHex)
				}
			}

			// Show extra bytes if any
			if remainder > 0 {
				extraStart := numAddresses * 20
				extraData := signersData[extraStart:]
				fmt.Printf("\n⚠️  Extra %d bytes at end: %x\n", remainder, extraData)
			}

		} else {
			fmt.Printf("⚠️  Extra data too short (%d bytes). Expected > 97 bytes for checkpoint.\n", len(extraBytes))
		}
		fmt.Printf("===========================\n")
	}

	if len(signers) == 0 {
		log.Fatal("Failed to extract signers from checkpoint block")
	}

	// Fetch recent blocks to build recents map
	rangeSize := uint64(10)
	fmt.Printf("\nFetching %d recent blocks for recents data...\n", rangeSize)
	recents := make(map[string]string)

	startBlock := blockNumber
	if blockNumber > rangeSize {
		startBlock = blockNumber - rangeSize
	}

	for i := startBlock; i <= blockNumber; i++ {
		var blockHeader BlockHeader
		hex := fmt.Sprintf("0x%x", i)
		err = client.Call(&blockHeader, "eth_getBlockByNumber", hex, false)
		if err == nil && blockHeader.Extra != "" {
			// Recover creator/signer from Extra field signature
			signer, recoverErr := recoverSigner(&blockHeader)
			if recoverErr == nil {
				recents[fmt.Sprintf("%d", i)] = signer

				// Also recover validator if present (double validation)
				if blockHeader.Validator != "" && len(blockHeader.Validator) > 2 {
					validator, validatorErr := recoverValidator(&blockHeader)
					if validatorErr == nil {
						fmt.Printf("  Block %d: creator=%s, validator=%s\n", i, signer, validator)
					} else {
						fmt.Printf("  Block %d: creator=%s, validator=N/A (%v)\n", i, signer, validatorErr)
					}
				} else {
					fmt.Printf("  Block %d: creator=%s \n", i, signer)
				}
			} else {
				fmt.Printf("  Block %d: failed to recover signer: %v\n", i, recoverErr)
				// Fallback to coinbase if recovery fails
				if blockHeader.Coinbase != "" {
					recents[fmt.Sprintf("%d", i)] = blockHeader.Coinbase
					fmt.Printf("  Block %d: using coinbase %s\n", i, blockHeader.Coinbase)
				}
			}
		}
	}

	// Create snapshot data structure
	snapshot := SnapshotData{
		Number:  blockNumber,
		Hash:    header.Hash,
		Signers: signers,
		Recents: recents,
		Votes:   []interface{}{},              // Empty for now - would need full chain analysis
		Tally:   make(map[string]interface{}), // Empty for now
		Config: map[string]interface{}{
			"period":              2,
			"epoch":               900,
			"reward":              250,
			"rewardCheckpoint":    900,
			"gap":                 5,
			"foudationWalletAddr": "0x0000000000000000000000000000000000000000",
		},
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal snapshot: %v", err)
	}

	// Save to file
	err = os.WriteFile(outputFile, data, 0644)
	if err != nil {
		log.Fatalf("Failed to write file: %v", err)
	}

	fmt.Printf("\nSuccessfully saved snapshot to %s\n", outputFile)
	fmt.Printf("File size: %d bytes\n", len(data))
	fmt.Printf("\nSnapshot summary:\n")
	fmt.Printf("  Block number: %d\n", snapshot.Number)
	fmt.Printf("  Block hash: %s\n", snapshot.Hash)
	fmt.Printf("  Signers: %d\n", len(snapshot.Signers))
	fmt.Printf("  Recent blocks tracked: %d\n", len(snapshot.Recents))
	fmt.Printf("\nNote: Votes and Tally are empty (requires full chain analysis)\n")
	fmt.Printf("This snapshot can be loaded in tests using LoadSnapshotFromFile()\n")
}
