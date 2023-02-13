package wts

import (
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poly "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

type WTSPublicParams struct {
	pp MTSPublicParams
}

type WTSParty struct {
	weight int
	wmax   int
	mtsp   MTSParty
}

type WTSSig struct {
	sigma  []MTSSig
	weight int
}

type WTS struct {
	crs  WTSPublicParams
	mts  []MTS // List of MTS instances
	wmax int   // Maximum allowable weight per signer
	ell  int   // Number of denomination
}

func (w *WTS) wts_key_gen(num_nodes int, g1 bls.G1Jac, g2 bls.G2Jac) MTSPublicParams {
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

// Takes the signing key and signs the message
func (w *WTS) wts_psign(msg Message, signer WTSParty) bls.G2Jac {
	var sig bls.G2Jac
	return sig
}

// Takes the signing key and signs the message
func (w *WTS) wts_pverify(sigma bls.G2Jac, signer WTSParty) bool {
	return true
}

// The combine function
func (w *WTS) wts_combine(sigmas []MTSSig) WTSSig {
	return WTSSig{}
}

// WTS global verify
// TODO: I think it might be better to make a class here
func (w *WTS) wts_gverify(msg Message, sigma WTSSig, weight int) bool {
	return true
}

// Only missing piece is the
