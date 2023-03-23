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

func TestKeyGen(t *testing.T) {
	n := 1 << 4
	ths := n - 1

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, ths, weights, crs)

	// Testing that public keys are generated correctly
	var tPk bls.G1Affine
	for i := 0; i < n; i++ {
		tPk.ScalarMultiplication(&w.crs.g1a, w.signers[i].sKey.BigInt(&big.Int{}))
		assert.Equal(t, tPk.Equal(&w.signers[i].pKeyAff), true)
	}

	// Checking whether the public key and hTaus is computed correctly
	lagH := GetLagAt(w.crs.tau, w.crs.H)
	var skTau fr.Element

	for i := 0; i < n; i++ {
		var skH fr.Element
		skH.Mul(&w.signers[i].sKey, &lagH[i])
		skTau.Add(&skTau, &skH)

		// Checking correctness of hTaus
		var hTau bls.G1Affine
		hTau.ScalarMultiplication(&w.crs.g1a, skH.BigInt(&big.Int{}))
		assert.Equal(t, hTau.Equal(&w.pp.hTaus[i]), true)
	}

	// Checking aggregated public key correctness
	var pComm bls.G1Affine
	pComm.ScalarMultiplication(&w.crs.g1a, skTau.BigInt(&big.Int{}))
	assert.Equal(t, pComm.Equal(&w.pp.pComm), true)

	// Checking whether lTaus are computed correcly or not
	lagL := GetLagAt(w.crs.tau, w.crs.L)
	for i := 0; i < n; i++ {
		var skLl fr.Element
		var lTauL bls.G1Affine
		for l := 0; l < n-1; l++ {
			skLl.Mul(&w.signers[i].sKey, &lagL[l])
			lTauL.ScalarMultiplication(&w.crs.g1a, skLl.BigInt(&big.Int{}))
			assert.Equal(t, lTauL.Equal(&w.pp.lTaus[i][l]), true)
		}
	}
}

func TestPreProcess(t *testing.T) {
	n := 1 << 4
	ths := n - 1
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, ths, weights, crs)

	// tau^n-1
	var zTau fr.Element
	zTau.Exp(w.crs.tau, big.NewInt(int64(n)))
	one := fr.One()
	zTau.Sub(&zTau, &one)

	var lhsG, rhsG, qi bls.G1Affine
	lagH := GetLagAt(w.crs.tau, w.crs.H)
	for i := 0; i < n; i++ {
		lhsG.ScalarMultiplication(&w.pp.pComm, lagH[i].BigInt(&big.Int{}))
		rhsG.ScalarMultiplication(&w.signers[i].pKeyAff, lagH[i].BigInt(&big.Int{}))
		qi.ScalarMultiplication(&w.pp.qTaus[i], zTau.BigInt(&big.Int{}))
		rhsG.Add(&rhsG, &qi)
		assert.Equal(t, lhsG.Equal(&rhsG), true)
	}
}

func TestWTSPSign(t *testing.T) {
	msg := []byte("hello world")
	var dst []byte
	roMsg, _ := bls.HashToG2(msg, dst)

	n := 4
	ths := n - 1
	weights := []int{15, 2, 4, 8}

	crs := GenCRS(n)
	w := NewWTS(n, ths, weights, crs)

	signers := make([]int, ths)
	sigmas := make([]bls.G2Jac, ths)
	for i := 0; i < ths; i++ {
		signers[i] = i
		sigmas[i] = w.psign(msg, w.signers[i])
		assert.Equal(t, w.pverify(roMsg, sigmas[i], w.signers[i].pKeyAff), true)
	}

	sig := w.combine(signers, sigmas)
	assert.Equal(t, w.gverify(msg, sig, ths), true)
}
