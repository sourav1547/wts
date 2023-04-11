// Adapted from: https://github.com/algorand/go-algorand/tree/ade1fead41c1dc298fc7c7640137d37825e1a7ae/crypto/compactcert
package compactcert

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"

	"github.com/consensys/gnark-crypto/signature"
)

// maxReveals is a bound on allocation and on numReveals to limit log computation
const maxReveals = 1024
const maxProofDigests = 20 * maxReveals

type Params struct {
	Msg          []byte
	ProvenWeight uint64
	SecKQ        uint64
}

type Participant struct {
	PK     signature.PublicKey
	Weight uint64
}

func (p Participant) MarshalBinary() ([]byte, error) {
	b := p.PK.Bytes()
	return binary.LittleEndian.AppendUint64(b, p.Weight), nil
}

type Participants []Participant

func (p Participants) Bytes() ([][]byte, error) {
	out := make([][]byte, 0, len(p))
	for _, part := range p {
		b, err := part.MarshalBinary()
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

type sigSlot struct {
	Sig []byte
	L   uint64
}

func (s sigSlot) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, len(s.Sig)+8)
	b = append(b, s.Sig...)
	return binary.LittleEndian.AppendUint64(b, s.L), nil
}

type Reveal struct {
	Party   Participant
	SigSlot sigSlot
}

func (r Reveal) Size() (s uint64) {
	b, _ := r.Party.MarshalBinary()
	s += uint64(len(b))
	b, _ = r.SigSlot.MarshalBinary()
	s += uint64(len(b))
	return
}

type Cert struct {
	SigCommit    []byte
	SignedWeight uint64
	SigProofs    [][]byte
	PartyProofs  [][]byte
	Reveals      map[uint64]Reveal
}

func (c *Cert) Size() (s uint64) {
	s += uint64(len(c.SigCommit))
	s += uint64(binary.Size(c.SignedWeight))
	for _, p := range c.SigProofs {
		s += uint64(len(p))
	}
	for _, p := range c.PartyProofs {
		s += uint64(len(p))
	}
	for _, r := range c.Reveals {
		s += r.Size()
	}
	return
}

func (c *Cert) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Cert) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(c)
}

// numReveals computes the number of reveals necessary to achieve the desired
// security parameters.  See section 8 of the “Compact Certificates”
// document for the analysis.
//
// numReveals is the smallest number that satisfies
//
// 2^-k >= 2^q * (provenWeight / signedWeight) ^ numReveals
//
// which is equivalent to the following:
//
// signedWeight ^ numReveals >= 2^(k+q) * provenWeight ^ numReveals
//
// To ensure that rounding errors do not reduce the security parameter,
// we compute the left-hand side with rounding-down, and compute the
// right-hand side with rounding-up.
func numReveals(signedWeight uint64, provenWeight uint64, secKQ uint64, bound uint64) (uint64, error) {
	n := uint64(0)

	sw := &bigFloatDn{}
	err := sw.setu64(signedWeight)
	if err != nil {
		return 0, err
	}

	pw := &bigFloatUp{}
	err = pw.setu64(provenWeight)
	if err != nil {
		return 0, err
	}

	lhs := &bigFloatDn{}
	err = lhs.setu64(1)
	if err != nil {
		return 0, err
	}

	rhs := &bigFloatUp{}
	rhs.setpow2(int32(secKQ))

	for {
		if lhs.ge(rhs) {
			return n, nil
		}

		if n >= bound {
			return 0, fmt.Errorf("numReveals(%d, %d, %d) > %d", signedWeight, provenWeight, secKQ, bound)
		}

		lhs.mul(sw)
		rhs.mul(pw)
		n++
	}
}

func (p Params) numReveals(signedWeight uint64) (uint64, error) {
	return numReveals(signedWeight, p.ProvenWeight, p.SecKQ, maxReveals)
}
