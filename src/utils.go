package wts

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// This function returns the lagrange coefficients for a given set of indices when evaluated at a specific point
// TODO: Have to optimize this
func get_lag_at(at int, indices []fr.Element) []fr.Element {
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
				i_fr := fr.NewElement(uint64(i))
				ii_fr := fr.NewElement(uint64(ii))
				diff.Sub(&i_fr, &ii_fr)
				deno.Mul(&deno, &diff)
			}
		}
		results[i].Div(&nume, &deno)
	}
	return results
}
