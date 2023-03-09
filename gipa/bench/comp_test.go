package wts

import (
	"math/big"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const LOG_N = 14

func BenchmarkTarget(b *testing.B) {
	n := 1 << LOG_N
	pkeys := make([]bls.G1Affine, n)
	ckeys := make([]bls.G2Affine, n)
	var sk fr.Element

	_, _, g1a, g2a := bls.Generators()
	var skInt big.Int

	for i := 0; i < n; i++ {
		sk.SetRandom()
		sk.ToBigIntRegular(&skInt)
		pkeys[i].ScalarMultiplication(&g1a, &skInt)

		sk.SetRandom()
		sk.ToBigIntRegular(&skInt)
		ckeys[i].ScalarMultiplication(&g2a, &skInt)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		targetCost(LOG_N, pkeys, ckeys)
	}
}

func BenchmarkSource(b *testing.B) {
	_, _, g1a, _ := bls.Generators()
	bases := make([][]bls.G1Affine, LOG_N)

	count := 1
	for i := 0; i < LOG_N; i++ {
		count = count * 3
		skeys := make([]fr.Element, count)
		for ii := 0; ii < count; ii++ {
			skeys[ii].SetRandom()
		}
		bases[i] = bls.BatchScalarMultiplicationG1(&g1a, skeys)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sourceCost(LOG_N, bases)
	}
}

func BenchmarkMultVer(b *testing.B) {
	_, _, g1a, _ := bls.Generators()
	n := 1 << LOG_N

	skeys := make([]fr.Element, n)
	pks := make([]bls.G1Jac, n)
	for ii := 0; ii < n; ii++ {
		skeys[ii].SetRandom()
	}
	pks_aff := bls.BatchScalarMultiplicationG1(&g1a, skeys)
	for ii := 0; ii < n; ii++ {
		pks[ii].FromAffine(&pks_aff[ii])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var apk bls.G1Jac
		for ii := 0; ii < n/2; ii++ {
			apk.AddAssign(&pks[ii])
		}
	}
}

func BenchmarkIPAVer(b *testing.B) {
	g1, _, _, _ := bls.Generators()

	alphas := make([]fr.Element, LOG_N)
	coms := make([]bls.G1Jac, 2*LOG_N)

	var ck fr.Element
	var ckInt big.Int
	var com bls.G1Jac

	ck.SetRandom()
	ck.ToBigIntRegular(&ckInt)
	com.ScalarMultiplication(&g1, &ckInt)

	for ii := 0; ii < LOG_N-1; ii++ {
		alphas[ii].SetRandom()
		ck.SetRandom()
		ck.ToBigIntRegular(&ckInt)
		coms[2*ii].ScalarMultiplication(&g1, &ckInt)

		ck.SetRandom()
		ck.ToBigIntRegular(&ckInt)
		coms[2*ii+1].ScalarMultiplication(&g1, &ckInt)
	}

	var (
		alphaSq    fr.Element
		alphaSqInv fr.Element
		aSqInt     big.Int
		aSqInvInt  big.Int
		com1       bls.G1Jac
	)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for ii := 0; ii < LOG_N; ii++ {
			alphaSq.Square(&alphas[ii])
			alphaSqInv.Inverse(&alphaSq)

			alphaSq.ToBigIntRegular(&aSqInt)
			alphaSqInv.ToBigIntRegular(&aSqInvInt)

			com1 = coms[2*ii]
			com1.ScalarMultiplication(&com1, &aSqInt)
			com.AddAssign(&com1)

			com1 = coms[2*ii+1]
			com1.ScalarMultiplication(&com1, &aSqInvInt)
			com.AddAssign(&com1)
		}
	}
}

func testSource(t *testing.T) {
	_, _, g1a, _ := bls.Generators()
	bases := make([][]bls.G1Affine, LOG_N)

	count := 1
	for i := 0; i < LOG_N; i++ {
		count = count * 3
		skeys := make([]fr.Element, count)
		for ii := 0; ii < count; ii++ {
			skeys[ii].SetRandom()
		}
		bases[i] = bls.BatchScalarMultiplicationG1(&g1a, skeys)
	}

	sourceCost(LOG_N, bases)
}

func testTarget(t *testing.T) {
	n := 1 << LOG_N
	pkeys := make([]bls.G1Affine, n)
	ckeys := make([]bls.G2Affine, n)
	var sk fr.Element

	_, _, g1a, g2a := bls.Generators()
	var skInt big.Int

	for i := 0; i < n; i++ {
		sk.SetRandom()
		sk.ToBigIntRegular(&skInt)
		pkeys[i].ScalarMultiplication(&g1a, &skInt)

		sk.SetRandom()
		sk.ToBigIntRegular(&skInt)
		ckeys[i].ScalarMultiplication(&g2a, &skInt)
	}

	targetCost(LOG_N, pkeys, ckeys)
}
