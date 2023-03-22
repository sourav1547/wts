// Adapted from https://github.com/algorand/go-algorand/tree/ade1fead41c1dc298fc7c7640137d37825e1a7ae/crypto/compactcert
package compactcert

import (
	"fmt"
	"hash"
	"math/big"

	"golang.org/x/crypto/sha3"
)

type SigSlots []sigSlot

func (s SigSlots) Bytes() ([][]byte, error) {
	b := make([][]byte, len(s))
	for i, slot := range s {
		slotb, err := slot.MarshalBinary()
		if err != nil {
			return nil, err
		}
		b[i] = slotb
	}
	return b, nil
}

type Builder[T PubKey] struct {
	Params

	sigs         SigSlots // Indexed by pos in participants
	signedWeight uint64
	participants []Participant[T]
	partyTree    *MerkleTree
	h            hash.Hash
	batchVerify  BatchVerifier[T]
}

func NewBuilder[T PubKey](params Params, parts []Participant[T], partyTree *MerkleTree) *Builder[T] {
	return &Builder[T]{
		Params:       params,
		sigs:         make([]sigSlot, len(parts)),
		participants: parts,
		partyTree:    partyTree,
		h:            sha3.New256(),
		batchVerify:  DefaultBatchVerifier[T],
	}
}

func (b *Builder[T]) WithHash(h hash.Hash) *Builder[T] {
	b.h = h
	return b
}

func (b *Builder[T]) WithBatchVerifier(v BatchVerifier[T]) *Builder[T] {
	b.batchVerify = v
	return b
}

func (b *Builder[T]) AddSignatures(pos []int, sigs [][]byte) error {
	pks := make([]T, len(pos))
	for i, p := range pos {
		if err := b.validatePart(p); err != nil {
			return err
		}
		pks[i] = b.participants[p].PK
	}
	if err := b.batchVerify(pks, b.Msg, sigs); err != nil {
		return err
	}
	for i, p := range pos {
		b.addSignature(p, sigs[i])
	}
	return nil
}

func (b *Builder[T]) AddSignature(pos int, sig []byte) error {
	if err := b.validatePart(pos); err != nil {
		return err
	}
	if b.participants[pos].PK.Verify(b.Msg, sig) != nil {
		return fmt.Errorf("invalid signature for party %d", pos)
	}

	b.addSignature(pos, sig)
	return nil
}

func (b *Builder[T]) validatePart(pos int) error {
	if b.sigs[pos].Sig != nil {
		return fmt.Errorf("already have signature for party %d", pos)
	}

	if pos >= (len(b.participants)) {
		return fmt.Errorf("invalid party position %d", pos)
	}

	if b.participants[pos].Weight == 0 {
		return fmt.Errorf("party %d has zero weight", pos)
	}
	return nil
}

func (b *Builder[T]) addSignature(pos int, sig []byte) {
	b.sigs[pos].Sig = sig
	b.signedWeight += b.participants[pos].Weight
}

func (b *Builder[T]) Build() (*Cert[T], error) {
	if b.signedWeight < b.Params.ProvenWeight {
		return nil, fmt.Errorf("signed weight %d < proven weight %d", b.signedWeight, b.Params.ProvenWeight)
	}

	// Compute L values for each signature
	b.sigs[0].L = 0
	for i := 1; i < len(b.sigs); i++ {
		b.sigs[i].L = b.sigs[i-1].L + b.participants[i-1].Weight
	}

	sigsBytes, err := b.sigs.Bytes()
	if err != nil {
		return nil, err
	}

	sigtree := NewMerkleTree().Build(sigsBytes)

	nr, err := b.numReveals(b.signedWeight)
	if err != nil {
		return nil, err
	}

	c := &Cert[T]{
		SigCommit:    sigtree.Root(),
		SignedWeight: b.signedWeight,
		Reveals:      make(map[uint64]Reveal[T], nr),
	}

	proofPositions := make([]int, 0, nr)
	msgHash := HashSum(b.h, b.Msg)

	// Choose the coin to reveal for each party
	for i := uint64(0); i < nr; i++ {
		choice := coinChoice{
			J:            i,
			SignedWeight: b.signedWeight,
			ProvenWeight: b.ProvenWeight,
			Sigcom:       c.SigCommit,
			Partcom:      b.partyTree.Root(),
			MsgHash:      msgHash,
		}

		coinWeight := hashCoin(choice)
		pos, err := b.coinIndex(coinWeight)
		if err != nil {
			return nil, err
		}

		// If we've already chosen a coin for this party, skip it.
		if _, alreadyRevealed := c.Reveals[pos]; alreadyRevealed {
			continue
		}

		c.Reveals[pos] = Reveal[T]{
			SigSlot: b.sigs[pos],
			Party:   b.participants[pos],
		}
		proofPositions = append(proofPositions, int(pos))
	}

	c.SigProofs, err = sigtree.Prove(proofPositions)
	if err != nil {
		return nil, err
	}

	c.PartyProofs, err = b.partyTree.Prove(proofPositions)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// coinIndex returns the position pos in the sigs array such that the sum
// of all signature weights before pos is less than or equal to coinWeight,
// but the sum of all signature weights up to and including pos exceeds
// coinWeight.
//
// coinIndex works by doing a binary search on the sigs array.
func (b *Builder[T]) coinIndex(coinWeight uint64) (uint64, error) {
	// if !b.sigsHasValidL {
	// 	return 0, fmt.Errorf("coinIndex: need valid L values")
	// }

	lo := uint64(0)
	hi := uint64(len(b.sigs))

again:
	if lo >= hi {
		return 0, fmt.Errorf("coinIndex: lo %d >= hi %d", lo, hi)
	}

	mid := (lo + hi) / 2
	if coinWeight < b.sigs[mid].L {
		hi = mid
		goto again
	}

	if coinWeight < b.sigs[mid].L+b.participants[mid].Weight {
		return mid, nil
	}

	lo = mid + 1
	goto again
}

// The coinChoice type defines the fields that go into the hash for choosing
// the index of the coin to reveal as part of the compact certificate.
type coinChoice struct {
	J            uint64
	SignedWeight uint64
	ProvenWeight uint64
	Sigcom       []byte
	Partcom      []byte
	MsgHash      []byte
}

func (cc coinChoice) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, 8+8+8)
	b = append(b, []byte{byte(cc.J), byte(cc.SignedWeight), byte(cc.ProvenWeight)}...)
	b = append(b, cc.Sigcom...)
	b = append(b, cc.Partcom...)
	b = append(b, cc.MsgHash...)
	return b, nil
}

// hashCoin returns a number in [0, choice.SignedWeight) with a nearly uniform
// distribution, "randomized" by all of the fields in choice.
func hashCoin(choice coinChoice) uint64 {
	choiceb, _ := choice.MarshalBinary()
	h := sha3.Sum256(choiceb)

	i := &big.Int{}
	i.SetBytes(h[:])

	w := &big.Int{}
	w.SetUint64(choice.SignedWeight)

	res := &big.Int{}
	res.Mod(i, w)
	return res.Uint64()
}
