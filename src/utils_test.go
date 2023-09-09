package wts

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
)

func TestGetLagAt(t *testing.T) {
	n := 12

	dom := fft.NewDomain(uint64(n))
	omega := dom.Generator
	omegas := make([]fr.Element, n)
	omegas[0] = fr.One()
	for i := 1; i < n; i++ {
		omegas[i].Mul(&omega, &omegas[i-1])
	}

	var tau fr.Element
	tau.SetRandom()

	expected := GetLagAtSlow(tau, omegas)
	actual := GetLagAt(tau, omegas)

	for i := 0; i < n; i++ {
		if !actual[i].Equal(&expected[i]) {
			t.Errorf("%d: Expected %s, got %s", i, expected[i].String(), actual[i].String())
		}
	}
}

func TestGetCoefficientsFromRoots(t *testing.T) {
	// (X-1)(X-2)(X-3)(X-4)(X-5)
	roots := []fr.Element{newElem(1), newElem(2), newElem(3), newElem(4), newElem(5)}
	// X^5 - 15X^4 + 85X^3 - 225X^2 + 274X - 120
	expected := []fr.Element{newElem(-120), newElem(274), newElem(-225), newElem(85), newElem(-15), newElem(1)}

	actual := GetCoefficientsFromRoots(roots)
	for i := 0; i < len(expected); i++ {
		if !actual[i].Equal(&expected[i]) {
			t.Errorf("%d: Expected %s, got %s", i, expected[i].String(), actual[i].String())
		}
	}
}

func TestMulPolynomials(t *testing.T) {
	// f(x) = 1 + 2x + 3x^2 + 4x^3
	f := []fr.Element{newElem(1), newElem(2), newElem(3), newElem(4)}
	// g(x) = 5 + 6x + 7x^2 + 8x^3
	g := []fr.Element{newElem(5), newElem(6), newElem(7), newElem(8)}
	expected := make([]fr.Element, len(f)+len(g)-1)
	for i := 0; i < len(expected); i++ {
		expected[i] = newElem(0)
	}
	for i := 0; i < len(f); i++ {
		for j := 0; j < len(g); j++ {
			expected[i+j].Add(&expected[i+j], new(fr.Element).Mul(&f[i], &g[j]))
		}
	}

	actual := MulPolynomials(f, g)
	for i := 0; i < len(expected); i++ {
		if !actual[i].Equal(&expected[i]) {
			t.Errorf("%d: Expected %s, got %s", i, expected[i].String(), actual[i].String())
		}
	}
}

func newElem(x int64) (z fr.Element) {
	z.SetInt64(x)
	return
}

func elementsString(e []fr.Element) string {
	s := "["
	for i := 0; i < len(e); i++ {
		s += e[i].String()
		if i != len(e)-1 {
			s += ", "
		}
	}
	s += "]"
	return s
}
