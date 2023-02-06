package wts

import (
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poly "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

// Trusted setup based key generation.
func key_gen_insec(num_nodes int) {
	f := make(poly.Polynomial, num_nodes)
	for i := 0; i < num_nodes; i++ {
		f[i].SetOne()
	}
}

type MTSPublicParams struct {
	coms           []bls.G1Jac
	coms_exp_k     []bls.G1Jac
	private_shares []fr.Element
	public_key_s   []bls.G1Jac
	public_key_k   []bls.G2Jac
}

type MTSParty struct {
	crs    []bls.G1Jac
	seckey fr.Element
	pubkey bls.G1Jac
}

func mts_key_gen(num_nodes int, g1 bls.G1Jac, g2 bls.G2Jac) MTSPublicParams {
	// build polynomial
	skeys := make(poly.Polynomial, num_nodes)
	for i := 0; i < num_nodes; i++ {
		skeys[i].SetRandom()
	}

	var k fr.Element
	var kint big.Int
	var gk bls.G1Jac
	gk.ScalarMultiplication(&gk, k.ToBigInt(&kint))

	return MTSPublicParams{}
}
