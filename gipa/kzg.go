package wts

import (
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poly "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

type KZG struct {
	n   int
	crs []bls.G1Affine
}

type KZGIPA struct {
	p_tau bls.G1Affine
	q_tau bls.G1Affine
}

// To generate KZG CRS
func NewKZG(n int, crs []bls.G1Affine) KZG {
	if len(crs) == 0 {
		// TOOD: To generate the CRS
		return KZG{
			n:   n,
			crs: crs,
		}
	}
	return KZG{n, crs}
}

func (k *KZG) commit(p poly.Polynomial) bls.G1Affine {
	return k.eval_exp(p)
}

func (k *KZG) prove(p poly.Polynomial, x fr.Element) (fr.Element, bls.G1Affine) {
	y := p.Eval(&x)
	qt := make(poly.Polynomial, k.n-1)
	return y, k.eval_exp(qt)
}

// We will specifically use this for GIPA, here the prover generates proof at a random evaluation point
func (k *KZG) comm_prove_rand(p poly.Polynomial) KZGIPA {
	var x fr.Element
	comm := k.commit(p)
	x.SetRandom() // TODO: to fix this, use commitment of the vector
	qt := make(poly.Polynomial, k.n-1)
	return KZGIPA{comm, k.eval_exp(qt)}
}

func (k *KZG) verify(com, pf bls.G1Affine, x, y fr.Element) bool {
	return true
}

// FIXME: Not sure we will need this in our implementation
func (k *KZG) batch_verify(comms, pfs []bls.G1Affine, xs, ys []fr.Element) bool {
	return true
}

// To evaluate the polynomial in the exponent
func (k *KZG) eval_exp(p poly.Polynomial) bls.G1Affine {
	return bls.G1Affine{}
}
