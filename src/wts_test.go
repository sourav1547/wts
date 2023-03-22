package wts

import (
	"math/big"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func TestGetOmega(t *testing.T) {
	n := 1 << 16
	seed := 0
	omega := GetOmega(n, seed)

	var omegaN fr.Element
	omegaN.Exp(omega, big.NewInt(int64(n)))
	one := fr.One()
	assert.Equal(t, omegaN, one, true)
}

func TestSetup(t *testing.T) {
	n := 1 << 2
	ths := n - 1
	weights := []int{15, 2, 4, 8}

	crs := GenCRS(n)
	w := NewWTS(n, ths, weights, crs)

	// Testing that public keys are generated correctly
	var tPk bls.G1Affine
	for i := 0; i < n; i++ {
		tPk.ScalarMultiplication(&w.crs.g1a, &w.signers[0].sKey)
		assert.Equal(t, tPk, w.signers[0].pKeyAff, true)
	}

	// Checking whether the public key is computed correctly
	lagH := GetLagAt(w.crs.tau, w.crs.H)
	var sk, skTau fr.Element
	for i := 0; i < n; i++ {
		sk.SetBigInt(&w.signers[i].sKey)
		skTau.Add(&skTau, sk.Mul(&sk, &lagH[i]))
	}
	var pComm bls.G1Affine
	pComm.ScalarMultiplication(&w.crs.g1a, skTau.ToBigInt(&big.Int{}))
	assert.Equal(t, pComm, w.pp.pComm)

	var zTau fr.Element
	zTau.Exp(w.crs.tau, big.NewInt(int64(n)))
	one := fr.One()
	zTau.Sub(&zTau, &one)

	var lhsG, rhsG, qi bls.G1Affine
	for i := 0; i < n; i++ {
		sk.SetBigInt(&w.signers[i].sKey)
		lhsG.ScalarMultiplication(&w.pp.pComm, lagH[i].ToBigInt(&big.Int{}))
		rhsG.ScalarMultiplication(&w.signers[i].pKeyAff, lagH[i].ToBigInt(&big.Int{}))
		qi.ScalarMultiplication(&w.pp.qTaus[i], zTau.ToBigInt(&big.Int{}))
		rhsG.Add(&rhsG, &qi)
		// assert.Equal(t, lhsG, rhsG)
	}
}

func TestWTSSign(t *testing.T) {
	msg := []byte("hello world")
	var dst []byte
	roMsg, _ := bls.HashToCurveG2SSWU(msg, dst)
	n := 4
	ths := n - 1
	weights := []int{15, 2, 4, 8}

	crs := GenCRS(n)
	w := NewWTS(n, ths, weights, crs)

	// Computing partial signatures and verifying them
	signers := make([]int, ths)
	sigmas := make([]bls.G2Jac, ths)
	for i := 0; i < ths; i++ {
		signers[i] = i
		sigmas[i] = w.psign(msg, w.signers[i])
		assert.Equal(t, w.pverify(roMsg, sigmas[i], w.signers[i].pKeyAff), true)
	}

	//Aggregating signatures
	sig := w.combine(signers, sigmas)

	// TODO: Verifying the IPA here

	// Final Signature verification
	var aggSigmaAff bls.G2Affine
	aggSigmaAff.FromJacobian(&sig.aggSig)

	P := []bls.G1Affine{sig.aggPk, w.crs.g1InvAff}
	Q := []bls.G2Affine{roMsg, aggSigmaAff}

	res, _ := bls.PairingCheck(P, Q)
	assert.Equal(t, res, true)
}
