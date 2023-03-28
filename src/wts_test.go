package wts

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/stretchr/testify/assert"
)

func TestFFT(t *testing.T) {
	const n = 1 << 3
	domain := fft.NewDomain(n)

	coset := domain.CosetTable
	g := domain.Generator
	var gi fr.Element
	fmt.Println("----------------")

	for i, val := range coset {
		// fmt.Println("Coset Table", val.ToBigIntRegular(&big.Int{}))
		gi.Exp(g, big.NewInt(int64(i)))
		if gi.Equal(&val) {
			fmt.Println("Match found!")
		}
	}
	fmt.Println("----------------")

	eval := make([]fr.Element, n)
	for i := 0; i < n>>1; i++ {
		eval[i] = fr.NewElement(uint64(1))
	}
	fmt.Println("Before FFT!")
	for i := 0; i < n; i++ {
		fmt.Println(eval[i].ToBigIntRegular(&big.Int{}))
	}
	domain.FFT(eval, fft.DIF)
	fmt.Println("After FFT!")
	for i := 0; i < n; i++ {
		fmt.Println(eval[i].ToBigIntRegular(&big.Int{}))
	}

	domain.FFTInverse(eval, fft.DIT)
	fmt.Println("After FFTInverse!")

	for i := 0; i < n; i++ {
		fmt.Println(eval[i].ToBigIntRegular(&big.Int{}))
	}
}

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

func TestBin(t *testing.T) {
	n := 1 << 4
	ths := n - 1
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, ths, weights, crs)

	bitV := make([]fr.Element, w.n)
	bitV[0].SetOne()
	count := 1
	for i := 1; i < w.n; i++ {
		if uint64(rand.Intn(2)) == 1 {
			bitV[i].SetOne()
			count += 1
		}
	}
	fmt.Println("Num signers", count)
	bTau, bNegTau, qTau := w.binaryPf(bitV)

	// Checking correctnes of bNegTau
	var bNegTauG1 bls.G1Affine
	bNegTauG1.Sub(&crs.g1a, &bTau)
	lhs, _ := bls.Pair([]bls.G1Affine{bNegTauG1}, []bls.G2Affine{crs.g2a})
	rhs, _ := bls.Pair([]bls.G1Affine{crs.g1a}, []bls.G2Affine{bNegTau})

	assert.Equal(t, lhs.Equal(&rhs), true, "Proving BNeg Correctness!")

	// Checking the binary relationship
	lhs, _ = bls.Pair([]bls.G1Affine{bTau}, []bls.G2Affine{bNegTau})
	rhs, _ = bls.Pair([]bls.G1Affine{qTau}, []bls.G2Affine{w.crs.vHTau})

	assert.Equal(t, lhs.Equal(&rhs), true, "Proving Binary relation!")
}

func TestWTSPSign(t *testing.T) {
	msg := []byte("hello world")
	var dst []byte
	roMsg, _ := bls.HashToG2(msg, dst)

	n := 1 << 4
	ths := n - 1
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, ths, weights, crs)

	signers := make([]int, ths)
	sigmas := make([]bls.G2Jac, ths)
	for i := 0; i < ths; i++ {
		signers[i] = i
		sigmas[i] = w.psign(msg, w.signers[i])
		assert.Equal(t, w.pverify(roMsg, sigmas[i], w.signers[i].pKeyAff), true)
	}

	bitV := make([]fr.Element, w.n)
	for i := 0; i < w.n; i++ {
		val := uint64(rand.Intn(2))
		fmt.Println(i, val)
		bitV[i] = fr.NewElement(val)
	}
	w.binaryPf(bitV)

	sig := w.combine(signers, sigmas)
	assert.Equal(t, w.gverify(msg, sig, ths), true)
}
