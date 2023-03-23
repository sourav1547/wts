package wts

import (
	"math"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func monomials(index int, alpha fr.Element, scalars []fr.Element) {
	var (
		alphaSq    fr.Element
		alphaSqInv fr.Element
	)

	iLen := int(math.Pow(float64(3), float64(index-1)))
	alphaSq.Square(&alpha)
	alphaSqInv.Inverse(&alphaSq)

	for i := 0; i < iLen; i++ {
		scalars[i+iLen].Mul(&alphaSq, &scalars[i])
		scalars[i+2*iLen].Mul(&alphaSqInv, &scalars[i])
	}
}

func sourceCost(logn int, bases [][]bls.G1Affine) []bls.G1Jac {
	chals := make([]fr.Element, logn)
	sLen := int(math.Pow(float64(3), float64(logn)))

	for i := 0; i < logn; i++ {
		chals[i].SetRandom()
	}

	resps := make([]bls.G1Jac, logn)
	scalars := make([]fr.Element, sLen)
	scalars[0] = fr.NewElement(uint64(1))
	count := 1
	for i := 0; i < logn; i++ {
		monomials(i-1, chals[i], scalars)
		count = count * 3
		resps[i].MultiExp(bases[i], scalars[:count], ecc.MultiExpConfig{})
	}
	return resps
}

func targetCost(logn int, pkeys []bls.G1Affine, ckeys []bls.G2Affine) []bls.GT {
	resps := make([]bls.GT, logn)

	var (
		chalFr    fr.Element
		chalInvFr fr.Element
		chal      big.Int
		chalInv   big.Int
	)

	for i := 0; i < logn; i++ {
		chalFr.SetRandom()
		chalInvFr.Inverse(&chalFr)
		chalFr.ToBigIntRegular(&chal)
		chalInvFr.ToBigIntRegular(&chalInv)

		mid := 1 << (logn - (i + 1))

		var (
			temp1  bls.G1Affine
			temp1i bls.G1Affine
			temp2  bls.G2Affine
			temp2i bls.G2Affine
		)

		for ii := 0; ii < mid; ii++ {
			temp1.ScalarMultiplication(&pkeys[ii], &chal)
			temp1i.ScalarMultiplication(&pkeys[mid+ii], &chalInv)
			pkeys[ii].Add(&temp1, &temp1i)

			temp2i.ScalarMultiplication(&ckeys[ii], &chalInv)
			temp2.ScalarMultiplication(&ckeys[mid+ii], &chal)
			ckeys[ii].Add(&temp2, &temp2i)
		}

		resps[i], _ = bls.Pair(pkeys[:mid], ckeys[mid:2*mid])
	}
	return resps
}
