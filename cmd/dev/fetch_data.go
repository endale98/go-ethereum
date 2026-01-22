package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

// LegacyRpcHeader mimics the Viction header structure returned by their RPC
// which contains the legacy validator fields.
type LegacyRpcHeader struct {
	ParentHash  common.Hash    `json:"parentHash"`
	UncleHash   common.Hash    `json:"sha3Uncles"`
	Coinbase    common.Address `json:"miner"`
	Root        common.Hash    `json:"stateRoot"`
	TxHash      common.Hash    `json:"transactionsRoot"`
	ReceiptHash common.Hash    `json:"receiptsRoot"`
	Bloom       hexutil.Bytes  `json:"logsBloom"`
	Difficulty  *hexutil.Big   `json:"difficulty"`
	Number      *hexutil.Big   `json:"number"`
	GasLimit    hexutil.Uint64 `json:"gasLimit"`
	GasUsed     hexutil.Uint64 `json:"gasUsed"`
	Time        hexutil.Uint64 `json:"timestamp"`
	Extra       hexutil.Bytes  `json:"extraData"`
	MixDigest   common.Hash    `json:"mixHash"`
	Nonce       hexutil.Bytes  `json:"nonce"`

	LegacyHash common.Hash `json:"hash"` // For verification
	// Legacy Fields (Source)
	Validators hexutil.Bytes `json:"validators"` // New Set
	Validator  hexutil.Bytes `json:"validator"`  // Sig
	Penalties  hexutil.Bytes `json:"penalties"`  // Slashing

}

// TargetHeaderData maps the legacy fields to the new naming convention
// required for Geth 1.15 integration.
type TargetHeaderData struct {
	ParentHash  common.Hash    `json:"parentHash"`
	UncleHash   common.Hash    `json:"sha3Uncles"`
	Coinbase    common.Address `json:"miner"`
	Root        common.Hash    `json:"stateRoot"`
	TxHash      common.Hash    `json:"transactionsRoot"`
	ReceiptHash common.Hash    `json:"receiptsRoot"`
	Bloom       hexutil.Bytes  `json:"logsBloom"`
	Difficulty  *hexutil.Big   `json:"difficulty"`
	Number      *hexutil.Big   `json:"number"`
	GasLimit    hexutil.Uint64 `json:"gasLimit"`
	GasUsed     hexutil.Uint64 `json:"gasUsed"`
	Time        hexutil.Uint64 `json:"timestamp"`
	Extra       hexutil.Bytes  `json:"extraData"`
	MixDigest   common.Hash    `json:"mixHash"`
	Nonce       hexutil.Bytes  `json:"nonce"`

	LegacyHash common.Hash `json:"hash"` // For verification
	// VICTION FIELDS (Renamed)
	NewAttestors hexutil.Bytes `json:"newAttestors"`
	Attestor     hexutil.Bytes `json:"attestor"`
	Penalties    hexutil.Bytes `json:"penalties"`
}

type EncodedHeader struct {
	Number uint64        `json:"number"`
	RLP    hexutil.Bytes `json:"rlp"`
}

func main() {
	rpcURL := flag.String("rpc", "https://rpc.viction.xyz", "RPC URL to fetch headers from")
	startFlag := flag.Uint64("start", 0, "Start block number")
	endFlag := flag.Uint64("end", 0, "End block number")
	flag.Parse()

	// 1. Connect to RPC
	ctx := context.Background()
	rpcClient, err := rpc.DialContext(ctx, *rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to RPC: %v", err)
	}
	defer rpcClient.Close()
	client := ethclient.NewClient(rpcClient)
	defer client.Close()

	if *startFlag == 0 && *endFlag == 0 {
		log.Fatal("Please specify -start and -end flags")
	}
	if *startFlag > *endFlag {
		log.Fatalf("Invalid range: start (%d) > end (%d)", *startFlag, *endFlag)
	}

	start := *startFlag
	end := *endFlag
	count := end - start + 1
	fmt.Printf("Fetching %d blocks from %d to %d\n", count, start, end)

	var legacies []LegacyRpcHeader
	var targets []TargetHeaderData
	var encoded []EncodedHeader

	for num := end; num >= start; num-- {
		// Use raw RPC call to decode into our custom LegacyRpcHeader struct
		var legacy LegacyRpcHeader
		if err := rpcClient.CallContext(ctx, &legacy, "eth_getBlockByNumber", hexutil.EncodeUint64(num), false); err != nil {
			log.Printf("Failed to fetch block %d: %v", num, err)
			continue // Or log.Fatal if strict
		}
		fmt.Printf(" Receive legacy block : %+v\n", legacy)

		vicMainnetHeader := types.Header{
			ParentHash:  legacy.ParentHash,
			UncleHash:   legacy.UncleHash,
			Coinbase:    legacy.Coinbase,
			Root:        legacy.Root,
			TxHash:      legacy.TxHash,
			ReceiptHash: legacy.ReceiptHash,
			Bloom:       types.Bloom(legacy.Bloom),
			Difficulty:  (*big.Int)(legacy.Difficulty),
			Number:      (*big.Int)(legacy.Number),
			GasLimit:    uint64(legacy.GasLimit),
			GasUsed:     uint64(legacy.GasUsed),
			Time:        uint64(legacy.Time),
			Extra:       legacy.Extra,
			MixDigest:   legacy.MixDigest,
		}

		vicMainnetHash := vicMainnetHeader.HashPoSV().Hex()
		fmt.Println("calculated hash : ", vicMainnetHash)

		// fmt.Println("hash : ", rlpHash)
		legacies = append(legacies, legacy)

		// Map to Target
		t := TargetHeaderData{
			ParentHash:  legacy.ParentHash,
			UncleHash:   legacy.UncleHash,
			Coinbase:    legacy.Coinbase,
			Root:        legacy.Root,
			TxHash:      legacy.TxHash,
			ReceiptHash: legacy.ReceiptHash,
			Bloom:       legacy.Bloom,
			Difficulty:  legacy.Difficulty,
			Number:      legacy.Number,
			GasLimit:    legacy.GasLimit,
			GasUsed:     legacy.GasUsed,
			Time:        legacy.Time,
			Extra:       legacy.Extra,
			MixDigest:   legacy.MixDigest,
			Nonce:       legacy.Nonce,
			LegacyHash:  legacy.LegacyHash,
			// BaseFee:      nil, // Set BaseFee to nil for now as per instructions (or keep logic)
			Attestor:     legacy.Validator,
			NewAttestors: legacy.Validators,
			Penalties:    legacy.Penalties,
		}

		targets = append(targets, t)

		// Create Geth Header for RLP encoding
		h := &types.Header{
			ParentHash:  t.ParentHash,
			UncleHash:   t.UncleHash,
			Coinbase:    t.Coinbase,
			Root:        t.Root,
			TxHash:      t.TxHash,
			ReceiptHash: t.ReceiptHash,
			Bloom:       types.Bloom(t.Bloom),
			Difficulty:  (*big.Int)(t.Difficulty),
			Number:      (*big.Int)(t.Number),
			GasLimit:    uint64(t.GasLimit),
			GasUsed:     uint64(t.GasUsed),
			Time:        uint64(t.Time),
			Extra:       t.Extra,
			MixDigest:   t.MixDigest,
			BaseFee:     nil, // Explicit
		}
		if len(t.Nonce) == 8 {
			copy(h.Nonce[:], t.Nonce)
		}
		// Viction Fields
		if len(t.Attestor) > 0 {
			b := []byte(t.Attestor)
			h.Attestor = b
		}
		if len(t.NewAttestors) > 0 {
			b := []byte(t.NewAttestors)
			h.NewAttestors = b
		}
		if len(t.Penalties) > 0 {
			b := []byte(t.Penalties)
			h.Penalties = b
		}

		rlpBytes, err := rlp.EncodeToBytes(h)
		if err != nil {
			log.Fatalf("Failed to encode block %d: %v", num, err)
		}
		encoded = append(encoded, EncodedHeader{
			Number: num,
			RLP:    hexutil.Bytes(rlpBytes),
		})

		fmt.Printf("Processed block %d\n", num)
		if num == start {
			break
		}
	}

	// Make dir if not exists
	outDir := "cmd/dev/testdata"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("Failed to create dir: %v", err)
	}

	writeJSON(filepath.Join(outDir, "viction_legacies.json"), legacies)
	writeJSON(filepath.Join(outDir, "viction_headers.json"), targets)
	writeJSON(filepath.Join(outDir, "encoded_headers.json"), encoded)

	fmt.Println("Success! 3 files generated in", outDir)
}

func writeJSON(path string, data interface{}) {
	file, err := os.Create(path)
	if err != nil {
		log.Fatalf("Failed to create file %s: %v", path, err)
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		log.Fatalf("Failed to encode JSON to %s: %v", path, err)
	}
}
