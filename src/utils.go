package wts

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type Message []byte

// This function returns the lagrange coefficients for a given set of indices when evaluated at a specific point
// TODO: Have to optimize this
func GetLagAt(at fr.Element, indices []fr.Element) []fr.Element {
	n := len(indices)
	results := make([]fr.Element, n)

	nu := fr.One()
	var res fr.Element
	for i := 0; i < n; i++ {
		res.Sub(&at, &indices[i])
		nu.Mul(&nu, &res)
	}

	var nume, div, deno, diff fr.Element
	for i := 0; i < n; i++ {
		div.Sub(&at, &indices[i])
		nume.Div(&nu, &div)
		deno = fr.One()
		for ii := 0; ii < n; ii++ {
			if i != ii {
				diff.Sub(&indices[i], &indices[ii])
				deno.Mul(&deno, &diff)
			}
		}
		results[i].Div(&nume, &deno)
	}
	return results
}

func GetOmega(n, seed int) fr.Element {
	var x, y, z fr.Element
	var nF, nFNegInv fr.Element

	x.SetRandom()
	nF = fr.NewElement(uint64(n))

	nFNegInv.Neg(&nF)
	nFNegInv.Inverse(&nFNegInv)
	y.Exp(x, nFNegInv.ToBigIntRegular(&big.Int{}))

	nF.Halve()
	z.Exp(y, nF.ToBigIntRegular(&big.Int{}))

	one := fr.One()
	if y.Equal(&one) || z.Equal(&one) {
		return GetOmega(n, seed+1)
	}
	return y
}
