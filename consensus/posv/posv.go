package posv

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

const (
	inmemorySnapshots      = 128 // Number of recent vote snapshots to keep in memory
	blockSignersCacheLimit = 9000
	M2ByteLength           = 4
	EpocBlockRandomize     = 900
)

type Masternode struct {
	Address common.Address
	Stake   *big.Int
}

type TradingService interface {
	GetTradingStateRoot(block *types.Block, author common.Address) (common.Hash, error)
	// GetTradingState(block *types.Block, author common.Address) (*tradingstate.TradingStateDB, error)
	// GetEmptyTradingState() (*tradingstate.TradingStateDB, error)
	HasTradingState(block *types.Block, author common.Address) bool
	// GetStateCache() tradingstate.Database
	// GetTriegc() *prque.Prque
	// ApplyOrder(header *types.Header, coinbase common.Address, chain ChainContext, statedb *state.StateDB, tomoXstatedb *tradingstate.TradingStateDB, orderBook common.Hash, order *tradingstate.OrderItem) ([]map[string]string, []*tradingstate.OrderItem, error)
	// UpdateMediumPriceBeforeEpoch(epochNumber uint64, tradingStateDB *tradingstate.TradingStateDB, statedb *state.StateDB) error
	IsSDKNode() bool
	// SyncDataToSDKNode(takerOrder *tradingstate.OrderItem, txHash common.Hash, txMatchTime time.Time, statedb *state.StateDB, trades []map[string]string, rejectedOrders []*tradingstate.OrderItem, dirtyOrderCount *uint64) error
	RollbackReorgTxMatch(txhash common.Hash) error
	GetTokenDecimal(chain ChainContext, statedb *state.StateDB, tokenAddr common.Address) (*big.Int, error)
}

type LendingService interface {
	GetLendingStateRoot(block *types.Block, author common.Address) (common.Hash, error)
	// GetLendingState(block *types.Block, author common.Address) (*lendingstate.LendingStateDB, error)
	HasLendingState(block *types.Block, author common.Address) bool
	// GetStateCache() lendingstate.Database
	// GetTriegc() *prque.Prque
	// ApplyOrder(header *types.Header, coinbase common.Address, chain ChainContext, statedb *state.StateDB, lendingStateDB *lendingstate.LendingStateDB, tradingStateDb *tradingstate.TradingStateDB, lendingOrderBook common.Hash, order *lendingstate.LendingItem) ([]*lendingstate.LendingTrade, []*lendingstate.LendingItem, error)
	// GetCollateralPrices(header *types.Header, chain ChainContext, statedb *state.StateDB, tradingStateDb *tradingstate.TradingStateDB, collateralToken common.Address, lendingToken common.Address) (*big.Int, *big.Int, error)
	// GetMediumTradePriceBeforeEpoch(chain ChainContext, statedb *state.StateDB, tradingStateDb *tradingstate.TradingStateDB, baseToken common.Address, quoteToken common.Address) (*big.Int, error)
	// ProcessLiquidationData(header *types.Header, chain ChainContext, statedb *state.StateDB, tradingState *tradingstate.TradingStateDB, lendingState *lendingstate.LendingStateDB) (updatedTrades map[common.Hash]*lendingstate.LendingTrade, liquidatedTrades, autoRepayTrades, autoTopUpTrades, autoRecallTrades []*lendingstate.LendingTrade, err error)
	// SyncDataToSDKNode(chain ChainContext, state *state.StateDB, block *types.Block, takerOrderInTx *lendingstate.LendingItem, txHash common.Hash, txMatchTime time.Time, trades []*lendingstate.LendingTrade, rejectedOrders []*lendingstate.LendingItem, dirtyOrderCount *uint64) error
	// UpdateLiquidatedTrade(blockTime uint64, result lendingstate.FinalizedResult, trades map[common.Hash]*lendingstate.LendingTrade) error
	RollbackLendingData(txhash common.Hash) error
}

// Posv proof-of-stake-voting protocol constants.
var (
	epochLength = uint64(900) // Default number of blocks after which to checkpoint and reset the pending votes

	extraVanity = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal   = 65 // Fixed number of extra-data suffix bytes reserved for signer seal

	nonceAuthVote = hexutil.MustDecode("0xffffffffffffffff") // Magic nonce number to vote on adding a new signer
	nonceDropVote = hexutil.MustDecode("0x0000000000000000") // Magic nonce number to vote on removing a signer.

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	diffInTurn = big.NewInt(2) // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1) // Block difficulty for out-of-turn signatures
)

// Posv is the proof-of-stake-voting consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
type Posv struct {
	config *PosvConfig    // Consensus engine configuration parameters
	db     ethdb.Database // Database to store and retrieve snapshot checkpoints

	recents             *lru.Cache[common.Hash, *Snapshot]      // Snapshots for recent block to speed up reorgs
	signatures          *lru.Cache[common.Hash, []byte]         // Signatures of recent blocks to speed up mining
	validatorSignatures *lru.Cache[common.Hash, common.Address] // Signatures of recent blocks to speed up mining
	verifiedHeaders     *lru.Cache[common.Hash, *types.Header]
	proposals           map[common.Address]bool // Current list of proposals we are pushing

	signer common.Address // Ethereum address of the signing key
	signFn SignerFn       // Signer function to authorize hashes with
	lock   sync.RWMutex   // Protects the signer fields

	BlockSigners          *lru.Cache[common.Address, *Snapshot]
	HookReward            func(chain ChainReader, state *state.StateDB, parentState *state.StateDB, header *types.Header) (error, map[string]interface{})
	HookPenalty           func(chain ChainReader, blockNumberEpoc uint64) ([]common.Address, error)
	HookPenaltyTIPSigning func(chain ChainReader, header *types.Header, candidate []common.Address) ([]common.Address, error)
	HookValidator         func(header *types.Header, signers []common.Address) ([]byte, error)
	HookVerifyMNs         func(header *types.Header, signers []common.Address) error
	// GetTomoXService            func() tradingService
	// GetLendingService          func() lendingService
	HookGetSignersFromContract func(blockHash common.Hash) ([]common.Address, error)
}

func New(config *PosvConfig, db ethdb.Database) *Posv {
	conf := *config
	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}
	blockSigners := lru.NewCache[common.Address, *Snapshot](blockSignersCacheLimit)
	recents := lru.NewCache[common.Hash, *Snapshot](inmemorySnapshots)
	signatures := lru.NewCache[common.Hash, []byte](inmemorySnapshots)
	validatorSignatures := lru.NewCache[common.Hash, common.Address](inmemorySnapshots)
	verifiedHeaders := lru.NewCache[common.Hash, *types.Header](inmemorySnapshots)
	return &Posv{
		config:              &conf,
		db:                  db,
		BlockSigners:        blockSigners,
		recents:             recents,
		signatures:          signatures,
		verifiedHeaders:     verifiedHeaders,
		validatorSignatures: validatorSignatures,
		proposals:           make(map[common.Address]bool),
	}
}
func (p *Posv) Signer() common.Address {
	return p.signer
}
func (p *Posv) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, p.signatures)
}
func (p *Posv) verifyHeadeWithCache(chain ChainReader, header *types.Header, parents []*types.Header, fullVerify bool) error {
	_, check := p.verifiedHeaders.Get(header.Hash())
	if check {
		return nil
	}
	err := p.verifyHeader(chain, header, parents, fullVerify)
	if err == nil {
		p.verifiedHeaders.Add(header.Hash(), header)
	}
	return err
}
func (p *Posv) verifyHeader(chain ChainReader, header *types.Header, parents []*types.Header, fullVerify bool) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()
	if fullVerify {
		// header.Number.Uint64() > p.config.Epoch && len(header.Validator) == 0 (check have validator in header)
		if header.Number.Uint64() > p.config.Epoch {
			return ErrNoValidatorSignature
		}
		if header.Time > uint64(time.Now().Unix()) {
			return ErrFutureBlock
		}
	}
	// Checkpoint blocks need to enforce zero beneficiary
	checkpoint := (number % p.config.Epoch) == 0
	if checkpoint && header.Coinbase != (common.Address{}) {
		return errInvalidCheckpointBeneficiary
	}
	// Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
	if !bytes.Equal(header.Nonce[:], nonceAuthVote) && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidVote
	}
	if checkpoint && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidCheckpointVote
	}
	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}
	// Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
	signersBytes := len(header.Extra) - extraVanity - extraSeal
	if !checkpoint && signersBytes != 0 {
		return errExtraSigners
	}
	if checkpoint && signersBytes%common.AddressLength != 0 {
		return errInvalidCheckpointSigners
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoSV
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// If all checks passed, validate any special fields for hard forks
	// [to-do] check fork hashes
	// if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
	// 	return err
	// }
	// All basic checks passed, verify cascading fields
	return p.verifyCascadingFields(chain, header, parents, fullVerify)
}

func (p *Posv) verifyCascadingFields(chain ChainReader, header *types.Header, parents []*types.Header, fullVerify bool) error {
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return ErrUnknownAncestor
	}
	if parent.Time+p.config.Period > header.Time {
		return ErrInvalidTimestamp
	}
	if number%p.config.Epoch != 0 {
		return p.verifySeal(chain, header, parents, fullVerify)
	}
	snap, err := p.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	signers := snap.GetSigners()
	err = p.checkSignersOnCheckpoint(chain, header, signers)
	if err == nil {
		return p.verifySeal(chain, header, parents, fullVerify)
	}

	signers, err = p.GetSignersFromContract(chain, header)
	if err != nil {
		return err
	}
	err = p.checkSignersOnCheckpoint(chain, header, signers)
	if err == nil {
		return p.verifySeal(chain, header, parents, fullVerify)
	}
	return err
}

// [to-do] implement verifySeal
func (p *Posv) verifySeal(chain ChainReader, header *types.Header, parents []*types.Header, fullVerify bool) error {
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// Retrive the snapshot needed to verify this header and cache it
	snap, err := p.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	// Resolve the authorization key and check against signers
	creator, err := ecrecover(header, p.signatures)
	if err != nil {
		return err
	}
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}

	difficulty := p.calcDifficulty(chain, parent, creator)
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty.Int64() != difficulty.Int64() {
			return errInvalidDifficulty
		}
	}
	masternodes := p.GetMasternodes(chain, header)
	mstring := []string{}
	for _, m := range masternodes {
		mstring = append(mstring, m.String())
	}
	nstring := []string{}
	for _, n := range snap.GetSigners() {
		nstring = append(nstring, n.String())
	}
	if _, ok := snap.Signers[creator]; !ok {
		valid := false
		for _, m := range masternodes {
			if m == creator {
				valid = true
				break
			}
		}
		if !valid {
			log.Debug("Unauthorized creator found", "block number", number, "creator", creator.String(), "masternodes", mstring, "snapshot from parent block", nstring)
			return errUnauthorized
		}
	}

	if len(masternodes) > 1 {
		for seen, recent := range snap.Recents {
			if recent == creator {
				// Signer is among recents, only fail if the current block doesn't shift it out
				// There is only case that we don't allow signer to create two continuous blocks.
				if limit := uint64(2); seen > number-limit {
					// Only take into account the non-epoch blocks
					if number%p.config.Epoch != 0 {
						return errUnauthorized
					}
				}
			}
		}
	}

	// header must contain validator info following double validation design
	// start checking from epoch 2nd.
	if header.Number.Uint64() > p.config.Epoch && fullVerify {
		validator, err := p.RecoverValidator(header)
		if err != nil {
			return err
		}

		// verify validator
		assignedValidator, err := p.GetValidator(creator, chain, header)
		if err != nil {
			return err
		}
		if validator != assignedValidator {
			log.Debug("Bad block detected. Header contains wrong pair of creator-validator", "creator", creator, "assigned validator", assignedValidator, "wrong validator", validator)
			return errFailedDoubleValidation
		}
	}
	return nil
}

func (p *Posv) GetMasternodes(chain consensus.ChainReader, header *types.Header) []common.Address {
	n := header.Number.Uint64()
	e := p.config.Epoch
	switch {
	case n%e == 0:
		return p.GetMasternodesFromCheckpointHeader(header, n, e)
	case n%e != 0:
		h := chain.GetHeaderByNumber(n - (n % e))
		return p.GetMasternodesFromCheckpointHeader(h, n, e)
	default:
		return []common.Address{}
	}
}

func (p *Posv) GetMasternodesFromCheckpointHeader(preCheckpointHeader *types.Header, n, e uint64) []common.Address {
	if preCheckpointHeader == nil {
		log.Info("Previous checkpoint's header is empty", "block number", n, "epoch", e)
		return []common.Address{}
	}
	masternodes := make([]common.Address, (len(preCheckpointHeader.Extra)-extraVanity-extraSeal)/common.AddressLength)
	for i := 0; i < len(masternodes); i++ {
		copy(masternodes[i][:], preCheckpointHeader.Extra[extraVanity+i*common.AddressLength:])
	}
	return masternodes
}

func (c *Posv) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return c.calcDifficulty(chain, parent, c.signer)
}

func (p *Posv) calcDifficulty(chain ChainReader, parent *types.Header, creator common.Address) *big.Int {
	len, preIndex, curIndex, _, err := p.YourTurn(chain, parent, creator)
	if err != nil {
		return big.NewInt(int64(len + curIndex - preIndex))
	}
	return big.NewInt(int64(len - Hop(len, preIndex, curIndex)))
}

func (p *Posv) YourTurn(chain ChainReader, parent *types.Header, signer common.Address) (int, int, int, bool, error) {
	masternodes := p.GetMasternodes(chain, parent)

	snap, err := p.GetSnapshot(chain, parent)
	if err != nil {
		log.Warn("Failed when trying to commit new work", "err", err)
		return 0, -1, -1, false, err
	}
	if len(masternodes) == 0 {
		return 0, -1, -1, false, errors.New("Masternodes not found")
	}
	pre := common.Address{}
	// masternode[0] has chance to create block 1
	preIndex := -1
	if parent.Number.Uint64() != 0 {
		pre, err = whoIsCreator(snap, parent)
		if err != nil {
			return 0, 0, 0, false, err
		}
		preIndex = position(masternodes, pre)
	}
	curIndex := position(masternodes, signer)
	if signer == p.signer {
		log.Debug("Masternodes cycle info", "number of masternodes", len(masternodes), "previous", pre, "position", preIndex, "current", signer, "position", curIndex)
	}
	for i, s := range masternodes {
		log.Debug("Masternode:", "index", i, "address", s.String())
	}
	if (preIndex+1)%len(masternodes) == curIndex {
		return len(masternodes), preIndex, curIndex, true, nil
	}
	return len(masternodes), preIndex, curIndex, false, nil
}

func (p *Posv) RecoverValidator(header *types.Header) (common.Address, error) {
	hash := header.Hash()
	if address, known := p.validatorSignatures.Get(hash); known {
		return common.Address(address), nil
	}
	// Retrieve the signature from the header.Validator
	// len equals 65 bytes
	if len(header.Validator) != extraSeal {
		return common.Address{}, ErrFailValidatorSignature
	}
	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(sigHash(header).Bytes(), header.Validator)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	p.validatorSignatures.Add(hash, signer)
	return signer, nil
}

func (p *Posv) GetValidator(creator common.Address, chain ChainReader, header *types.Header) (common.Address, error) {
	epoch := p.config.Epoch
	no := header.Number.Uint64()
	cpNo := no
	if no%epoch != 0 {
		cpNo = no - (no % epoch)
	}
	if cpNo == 0 {
		return common.Address{}, nil
	}
	cpHeader := chain.GetHeaderByNumber(cpNo)
	if cpHeader == nil {
		if no%epoch == 0 {
			cpHeader = header
		} else {
			return common.Address{}, fmt.Errorf("couldn't find checkpoint header")
		}
	}
	m, err := GetM1M2FromCheckpointHeader(cpHeader, header, chain.Config())
	if err != nil {
		return common.Address{}, err
	}
	return m[creator], nil
}

// [to-do] implement checkSignersOnCheckpoint
func (p *Posv) checkSignersOnCheckpoint(chain ChainReader, header *types.Header, signers []common.Address) error {
	return nil
}

// [to-do] implement GetSignersFromContract
func (p *Posv) GetSignersFromContract(chain ChainReader, header *types.Header) ([]common.Address, error) {
	return nil, nil
}

// [to-do] implement snapshot
func (p *Posv) snapshot(chain ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	return nil, nil
}

func (p *Posv) VerifyHeader(chain ChainReader, header *types.Header, fullVerify bool) error {
	return nil
}
func (p *Posv) VerifyHeaders(chain ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {

	return nil, nil
}
func (p *Posv) VerifyUncles(chain ChainReader, block *types.Block) error {
	return nil
}
func (p *Posv) VerifySeal(chain ChainReader, header *types.Header) error {
	return nil
}
func (p *Posv) Prepare(chain ChainReader, header *types.Header) error {
	return nil
}

func ecrecover(header *types.Header, sigcache *lru.Cache[common.Hash, []byte]) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return common.Address(address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(sigHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer.Bytes())
	return signer, nil
}

// [to-do] not sure about block rlp encode for newer header version
func sigHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()

	rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
		header.Validator,
	})
	hasher.Sum(hash[:0])
	return hash
}

func GetM1M2FromCheckpointHeader(checkpointHeader *types.Header, currentHeader *types.Header, config *params.ChainConfig) (map[common.Address]common.Address, error) {
	if checkpointHeader.Number.Uint64()%EpocBlockRandomize != 0 {
		return nil, errors.New("This block is not checkpoint block epoc.")
	}
	// Get signers from this block.
	masternodes := GetMasternodesFromCheckpointHeader(checkpointHeader)
	validators := ExtractValidatorsFromBytes(checkpointHeader.Validators)
	m1m2, _, err := getM1M2(masternodes, validators, currentHeader, config)
	if err != nil {
		return map[common.Address]common.Address{}, err
	}
	return m1m2, nil
}

func GetMasternodesFromCheckpointHeader(checkpointHeader *types.Header) []common.Address {
	masternodes := make([]common.Address, (len(checkpointHeader.Extra)-extraVanity-extraSeal)/common.AddressLength)
	for i := 0; i < len(masternodes); i++ {
		copy(masternodes[i][:], checkpointHeader.Extra[extraVanity+i*common.AddressLength:])
	}
	return masternodes
}

func getM1M2(masternodes []common.Address, validators []int64, currentHeader *types.Header, config *params.ChainConfig) (map[common.Address]common.Address, uint64, error) {
	m1m2 := map[common.Address]common.Address{}
	maxMNs := len(masternodes)
	moveM2 := uint64(0)
	if len(validators) < maxMNs {
		return nil, moveM2, errors.New("len(m2) is less than len(m1)")
	}
	if maxMNs > 0 {
		isForked := config.IsTIPRandomize(currentHeader.Number)
		if isForked {
			moveM2 = ((currentHeader.Number.Uint64() % config.Posv.Epoch) / uint64(maxMNs)) % uint64(maxMNs)
		}
		for i, m1 := range masternodes {
			m2Index := uint64(validators[i] % int64(maxMNs))
			m2Index = (m2Index + moveM2) % uint64(maxMNs)
			m1m2[m1] = masternodes[m2Index]
		}
	}
	return m1m2, moveM2, nil
}
