package wts

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Returns the Hamming weight of an integer
func HamWeight(a int) int {
	wt := 0
	for a > 0 {
		wt = wt + a&1
		a = a >> 1
	}
	return wt
}

// Returns the positions of 1's in the binary encoding in ascending order
func BinPos(a int) []int {
	var pos []int
	for i := 0; a > 0; i++ {
		if a&1 == 1 {
			pos = append(pos, i)
		}
		a = a >> 1
	}
	return pos
}

// This function returns the lagrange coefficients for a given set of indices when evaluated at a specific point
// TODO: Have to optimize this
func GetLagAt(at int, indices []fr.Element) []fr.Element {
	n := len(indices)
	results := make([]fr.Element, n)

	nu := fr.NewElement(1)
	var res fr.Element
	fr_at := fr.NewElement(uint64(at))
	for i := 0; i < n; i++ {
		res.Sub(&fr_at, &indices[i])
		nu.Mul(&nu, &res)
	}

	var nume, div, deno, diff fr.Element
	for i := 0; i < n; i++ {
		div.Sub(&fr_at, &indices[i])
		nume.Div(&nu, &div)
		deno = fr.NewElement(1)
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
