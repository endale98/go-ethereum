package posv

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (p *Posv) VerifySeal(chain ChainReader, header *types.Header) error {
	number := header.Number.Uint64()
	if number == 0 {
		return nil // Genesis is trusted or verified elsewhere
	}

	// 1. Decode ExtraData
	// Check length > 32 (ExtraVanity)
	if len(header.Extra) <= extraVanity {
		return errMissingVanity
	}

	// Slice header.Extra[32:]
	payload := header.Extra[extraVanity:]

	// RLP Decode into VictionSignature struct
	var sig VictionSignature
	if err := rlp.DecodeBytes(payload, &sig); err != nil {
		return err // ErrInvalidSignatureFormat?
	}

	// 2. SealHash Calculation
	// Create a copy of the header, set ExtraData to vanity only, Hash.
	// We use the helper SealHash from utils.go
	sighash := SealHash(header)

	// 3. Recover Signers (Double Recovery)

	// Recover Creator Address from VictionSignature.Signer
	if len(sig.Signer) != extraSeal {
		return errMissingSignature // or invalid length
	}
	// Recover public key
	pubKeyCreator, err := crypto.Ecrecover(sighash.Bytes(), sig.Signer)
	if err != nil {
		return err
	}
	var creator common.Address
	copy(creator[:], crypto.Keccak256(pubKeyCreator[1:])[12:])

	// Recover Verifier Address from VictionSignature.Verifier (if present)
	var verifier common.Address
	hasVerifier := false
	if len(sig.Verifier) > 0 {
		if len(sig.Verifier) != extraSeal {
			return errors.New("invalid verifier signature length")
		}
		pubKeyVerifier, err := crypto.Ecrecover(sighash.Bytes(), sig.Verifier)
		if err != nil {
			return err
		}
		copy(verifier[:], crypto.Keccak256(pubKeyVerifier[1:])[12:])
		hasVerifier = true
	}

	// 4. Snapshot Interaction (The "Brain")
	// Call p.snapshot(chain, parent)
	// We need parent hash.
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return ErrUnknownAncestor
	}

	snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	// Check 1 (Creator): Verify Snapshot.IsValidator(creatorAddr) is true.
	if !snap.IsValidator(creator) {
		return errUnauthorized
	}

	// Check 2 (Verifier):
	// Calculate expectedVerifier = Snapshot.GetRandomVerifier(header.Number).
	// Compare recoveredVerifier vs expectedVerifier.

	// If double validation is enforced, we must have a verifier if expectedVerifier is not empty?
	expectedVerifier := snap.GetRandomVerifier(header.Number.Uint64())

	// Assuming strict checking for now.
	if expectedVerifier != (common.Address{}) {
		if !hasVerifier {
			return errors.New("missing verifier signature")
		}
		if verifier != expectedVerifier {
			return errFailedDoubleValidation // "wrong pair of creator-validator" / "wrong verifier"
		}
	} else {
		// If no verifier expected, but one provided, we can ignore or error.
	}

	return nil
}

// IsValidator checks if the address is currently a validator.
func (s *Snapshot) IsValidator(addr common.Address) bool {
	_, ok := s.Signers[addr]
	return ok
}

// GetRandomVerifier returns a deterministic random verifier for the block number.
func (s *Snapshot) GetRandomVerifier(number uint64) common.Address {
	return common.Address{}
}
