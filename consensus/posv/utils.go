package posv

import (
	"bytes"
	"errors"
	"reflect"
	"sort"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

func compareSignersLists(list1 []common.Address, list2 []common.Address) bool {
	if len(list1) == 0 && len(list2) == 0 {
		return true
	}
	sort.Slice(list1, func(i, j int) bool {
		return list1[i].String() <= list1[j].String()
	})
	sort.Slice(list2, func(i, j int) bool {
		return list2[i].String() <= list2[j].String()
	})
	return reflect.DeepEqual(list1, list2)
}

func position(list []common.Address, x common.Address) int {
	for i, item := range list {
		if item == x {
			return i
		}
	}
	return -1
}

func (p *Posv) GetPeriod() uint64 { return p.config.Period }

func whoIsCreator(snap *Snapshot, header *types.Header) (common.Address, error) {
	if header.Number.Uint64() == 0 {
		return common.Address{}, errors.New("Don't take block 0")
	}
	m, err := ecrecover(header, snap.sigcache)
	if err != nil {
		return common.Address{}, err
	}
	return m, nil
}

// Extract validators from byte array.
func ExtractValidatorsFromBytes(byteValidators []byte) []int64 {
	lenValidator := len(byteValidators) / M2ByteLength
	var validators []int64
	for i := 0; i < lenValidator; i++ {
		trimByte := bytes.Trim(byteValidators[i*M2ByteLength:(i+1)*M2ByteLength], "\x00")
		intNumber, err := strconv.Atoi(string(trimByte))
		if err != nil {
			log.Error("Can not convert string to integer", "error", err)
			return []int64{}
		}
		validators = append(validators, int64(intNumber))
	}

	return validators
}

func Hop(len, pre, cur int) int {
	switch {
	case pre < cur:
		return cur - (pre + 1)
	case pre > cur:
		return (len - pre) + (cur - 1)
	default:
		return len - 1
	}
}

func (p *Posv) CheckMNTurn(chain consensus.ChainReader, parent *types.Header, signer common.Address) bool {
	masternodes := p.GetMasternodes(chain, parent)

	snap, err := p.GetSnapshot(chain, parent)
	if err != nil {
		log.Warn("Failed when trying to commit new work", "err", err)
		return false
	}
	if len(masternodes) == 0 {
		return false
	}
	pre := common.Address{}
	// masternode[0] has chance to create block 1
	preIndex := -1
	if parent.Number.Uint64() != 0 {
		pre, err = whoIsCreator(snap, parent)
		if err != nil {
			return false
		}
		preIndex = position(masternodes, pre)
	}
	curIndex := position(masternodes, signer)
	if (preIndex)%len(masternodes) == curIndex {
		return true
	}
	return false
}

func (p *Posv) GetSnapshot(chain consensus.ChainReader, header *types.Header) (*Snapshot, error) {
	number := header.Number.Uint64()
	log.Trace("take snapshot", "number", number, "hash", header.Hash())
	snap, err := p.snapshot(chain, number, header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap, nil
}

func (p *Posv) StoreSnapshot(snap *Snapshot) error {
	return snap.store(p.db)
}
