package posv

import "github.com/ethereum/go-ethereum/common"

// PosvConfig is the consensus engine configs for proof-of-stake-voting based sealing.
type PosvConfig struct {
	Period              uint64         `json:"period"`              // Number of seconds between blocks to enforce
	Epoch               uint64         `json:"epoch"`               // Epoch length to reset votes and checkpoint
	Reward              uint64         `json:"reward"`              // Block reward - unit Ether
	RewardCheckpoint    uint64         `json:"rewardCheckpoint"`    // Checkpoint block for calculate rewards.
	Gap                 uint64         `json:"gap"`                 // Gap time preparing for the next epoch
	FoudationWalletAddr common.Address `json:"foudationWalletAddr"` // Foundation Address Wallet
}
