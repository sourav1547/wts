package wts

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func BenchmarkCompF(b *testing.B) {
	logN := 15
	n := 1 << logN

	fs := make([]fr.Element, n*logN)
	for i := 0; i < n*logN; i++ {
		fs[i].SetRandom()
	}

	for i := 0; i < b.N; i++ {
		for j := 0; j < 4; j++ {
			var sum fr.Element
			for ii := 0; ii < n*logN; ii++ {
				sum.Add(&sum, &fs[ii])
			}
		}
	}
}

func BenchmarkCompG1(b *testing.B) {
	logN := 15
	n := 1 << logN
	g1, _, _, _ := bls.Generators()

	var exp fr.Element
	gs := make([]bls.G1Jac, n)
	for i := 0; i < n; i++ {
		exp.SetRandom()
		gs[i].ScalarMultiplication(&g1, exp.BigInt(&big.Int{}))
	}

	for i := 0; i < b.N; i++ {
		var sumG bls.G1Jac
		for ii := 0; ii < n; ii++ {
			sumG.AddAssign(&gs[ii])
		}
	}
}

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

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, weights, crs)

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
			assert.Equal(t, lTauL.Equal(&w.pp.lTaus[l][i]), true)
		}
	}
}

func BenchmarkCComp1(b *testing.B) {
	n := 1 << 15
	scalars := make([]fr.Element, n)
	b.ResetTimer()
	for i := 0; i < n; i++ {
		scalars[i].SetRandom()
	}
}

func BenchmarkCComp2(b *testing.B) {
	n := 1 << 15
	scalars := make([]fr.Element, n)

	b.ResetTimer()
	for i := 0; i < n; i++ {
		scalars[i].SetOne()
	}
}

func BenchmarkGenCRS(b *testing.B) {
	n := 1 << 10
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}
	crs := GenCRS(n)
	w := NewWTS(n, weights, crs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.preProcess()
	}
}

func TestPreProcess(t *testing.T) {
	n := 1 << 5
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, weights, crs)
	w.preProcess()

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

func TestBin(t *testing.T) {
	n := 1 << 5
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, weights, crs)
	w.preProcess()

	var bTau bls.G1Affine
	var bNegTau bls.G2Affine

	var signers []int
	ths := 0
	for i := 0; i < n; i++ {
		if rand.Intn(2) == 1 {
			signers = append(signers, i)
			// sigmas = append(sigmas, w.psign(msg, w.signers[i]))
			bTau.Add(&bTau, &crs.lagHTaus[i])
			bNegTau.Add(&bNegTau, &crs.lag2HTaus[i])
			ths += weights[i]
		}
	}
	bTauG2 := bNegTau
	bNegTau.Sub(&crs.g2a, &bNegTau)
	qTau := w.binaryPf(signers)
	fmt.Println("Signers ", len(signers), "Threshold", ths)

	var bNegTauG1 bls.G1Affine
	bNegTauG1.Sub(&w.crs.g1a, &bTau)
	lhs, _ := bls.Pair([]bls.G1Affine{bNegTauG1}, []bls.G2Affine{crs.g2a})
	rhs, _ := bls.Pair([]bls.G1Affine{crs.g1a}, []bls.G2Affine{bNegTau})
	assert.Equal(t, lhs.Equal(&rhs), true, "Proving BNeg Correctness!")

	// Checking the binary relation
	lhs, _ = bls.Pair([]bls.G1Affine{bTau}, []bls.G2Affine{bNegTau})
	rhs, _ = bls.Pair([]bls.G1Affine{qTau}, []bls.G2Affine{w.crs.vHTau})
	assert.Equal(t, lhs.Equal(&rhs), true, "Proving Binary relation!")

	// Checking weights relation
	qwTau, qrwTau := w.weightsPf(signers)

	var gThs bls.G1Affine
	nInv := fr.NewElement(uint64(w.n))
	nInv.Inverse(&nInv)
	gThs.ScalarMultiplication(&w.crs.g1a, big.NewInt(int64(ths)))
	gThs.ScalarMultiplication(&gThs, nInv.BigInt(&big.Int{}))

	lhs, _ = bls.Pair([]bls.G1Affine{w.pp.wTau}, []bls.G2Affine{bTauG2})
	rhs, _ = bls.Pair([]bls.G1Affine{qwTau, qrwTau, gThs}, []bls.G2Affine{w.crs.vHTau, w.crs.g2Tau, w.crs.g2a})
	assert.Equal(t, lhs.Equal(&rhs), true, "Proving weights!")
}

func TestWTSPSign(t *testing.T) {
	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte{})

	n := 1 << 5
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, weights, crs)
	w.preProcess()

	var signers []int
	var sigmas []bls.G2Jac
	ths := 0
	for i := 0; i < n; i++ {
		if rand.Intn(2) == 1 {
			signers = append(signers, i)
			sigmas = append(sigmas, w.psign(msg, w.signers[i]))
			ths += weights[i]
		}
	}

	for i, idx := range signers {
		assert.Equal(t, w.pverify(roMsg, sigmas[i], w.signers[idx].pKeyAff), true)
	}
	fmt.Println("Signers ", len(signers), "Threshold", ths)

	sig := w.combine(signers, sigmas)
	assert.Equal(t, w.gverify(msg, sig, ths), true)
}

func BenchmarkCombine(b *testing.B) {
	msg := []byte("hello world")
	n := 1 << 12
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, weights, crs)
	w.preProcess()

	var signers []int
	var sigmas []bls.G2Jac
	ths := 0
	for i := 0; i < n; i++ {
		if rand.Intn(2) == 1 {
			signers = append(signers, i)
			sigmas = append(sigmas, w.psign(msg, w.signers[i]))
			ths += weights[i]
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.combine(signers, sigmas)
	}
}
