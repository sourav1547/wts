package wts

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func TestKeyGen(t *testing.T) {
	num_nodes := 4
	g1, g2, _, _ := bls12381.Generators()
	mts_key_gen(num_nodes, g1, g2)
}
