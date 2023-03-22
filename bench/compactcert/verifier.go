package compactcert

import (
	"fmt"
	"hash"

	"golang.org/x/crypto/sha3"
)

type Verifier[T PubKey] struct {
	Params

	partyRoot   []byte
	h           hash.Hash
	batchVerify BatchVerifier[T]
}

func NewVerifier[T PubKey](params Params, partyRoot []byte) *Verifier[T] {
	return &Verifier[T]{
		Params:      params,
		partyRoot:   partyRoot,
		h:           sha3.New256(),
		batchVerify: DefaultBatchVerifier[T],
	}
}

func (v *Verifier[T]) WithHash(h hash.Hash) *Verifier[T] {
	v.h = h
	return v
}

func (v *Verifier[T]) WithBatchVerifier(batchVerifier BatchVerifier[T]) *Verifier[T] {
	v.batchVerify = batchVerifier
	return v
}

// Verify checks if c is a valid compact certificate for the message
// and participants that were used to construct the Verifier[T].
func (v *Verifier[T]) Verify(c *Cert[T]) error {
	if c.SignedWeight <= v.ProvenWeight {
		return fmt.Errorf("cert signed weight %d <= proven weight %d", c.SignedWeight, v.ProvenWeight)
	}

	// Verify all of the reveals
	sigs := make(map[int][]byte)
	parts := make(map[int][]byte)
	pks := make([]T, 0, len(c.Reveals))
	sigsList := make([][]byte, 0, len(c.Reveals))
	for pos, r := range c.Reveals {
		slotb, err := r.SigSlot.MarshalBinary()
		if err != nil {
			return err
		}
		partb, err := r.Party.MarshalBinary()
		if err != nil {
			return err
		}
		sigs[int(pos)] = HashSum(v.h, slotb)
		parts[int(pos)] = HashSum(v.h, partb)

		pks = append(pks, r.Party.PK)
		sigsList = append(sigsList, r.SigSlot.Sig)
		// if r.Party.PK.Verify(v.Msg, r.SigSlot.Sig) != nil {
		// 	return fmt.Errorf("signature in reveal pos %d does not verify", pos)
		// }
	}

	if err := v.batchVerify(pks, v.Msg, sigsList); err != nil {
		return fmt.Errorf("signature in reveal does not verify\n%s", err)
	}

	if err := VerifyMerkleTree(c.SigCommit, sigs, c.SigProofs); err != nil {
		return fmt.Errorf("signature commit does not verify\n%s", err)
	}

	if VerifyMerkleTree(v.partyRoot, parts, c.PartyProofs) != nil {
		return fmt.Errorf("party commit does not verify")
	}

	// Verify that the reveals contain the right coins
	nr, err := v.numReveals(c.SignedWeight)
	if err != nil {
		return err
	}

	msgHash := HashSum(v.h, v.Msg)

	for j := uint64(0); j < nr; j++ {
		choice := coinChoice{
			J:            j,
			SignedWeight: c.SignedWeight,
			ProvenWeight: v.ProvenWeight,
			Sigcom:       c.SigCommit,
			Partcom:      v.partyRoot,
			MsgHash:      msgHash,
		}

		coin := hashCoin(choice)
		matchingReveal := false
		for _, r := range c.Reveals {
			if r.SigSlot.L <= coin && coin < r.SigSlot.L+r.Party.Weight {
				matchingReveal = true
				break
			}
		}

		if !matchingReveal {
			return fmt.Errorf("no reveal for coin %d at %d", j, coin)
		}
	}

	return nil
}
