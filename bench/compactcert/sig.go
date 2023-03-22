package compactcert

import (
	"bytes"
	"encoding"
	"encoding/gob"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/random"
)

type PubKey interface {
	encoding.BinaryMarshaler

	Verify(msg []byte, sig []byte) error
}

type Signer interface {
	PubKey

	Sign(msg []byte) ([]byte, error)
}

type BatchVerifier[T PubKey] func(keys []T, msg []byte, sigs [][]byte) error

func DefaultBatchVerifier[T PubKey](keys []T, msg []byte, sigs [][]byte) error {
	for i, key := range keys {
		if err := key.Verify(msg, sigs[i]); err != nil {
			return err
		}
	}
	return nil
}

var bn256Suite = bn256.NewSuite()

func NewBLSSigner() *BLSSigner {
	sk, pk := bls.NewKeyPair(bn256Suite, random.New())
	return &BLSSigner{
		BLSPubKey: BLSPubKey{pk},
		sk:        sk,
	}
}

type BLSPubKey struct {
	kyber.Point
}

func (pk BLSPubKey) Verify(msg []byte, sig []byte) error {
	return bls.Verify(bn256Suite, pk.Point, msg, []byte(sig))
}

type BLSSigner struct {
	BLSPubKey
	sk kyber.Scalar
}

func (s BLSSigner) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *BLSSigner) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(s)
}

func (s BLSSigner) Sign(msg []byte) ([]byte, error) {
	sig, err := bls.Sign(bn256Suite, s.sk, msg)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func BLSBatchVerifier(blsPKs []BLSPubKey, msg []byte, sigs [][]byte) error {
	pks := make([]kyber.Point, len(blsPKs))
	for i, pk := range blsPKs {
		pks[i] = pk.Point
	}
	aggPKs := bls.AggregatePublicKeys(bn256Suite, pks...)
	aggSigs, err := bls.AggregateSignatures(bn256Suite, sigs...)
	if err != nil {
		return err
	}
	return bls.Verify(bn256Suite, aggPKs, msg, aggSigs)
}
