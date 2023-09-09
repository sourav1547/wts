package wts

import (
	"fmt"
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
	tau.SetInt64(2)

	indices := []int{1, 5, 7, 9, 11}

	expectedOmegas := make([]fr.Element, len(indices))
	for i := 0; i < len(indices); i++ {
		expectedOmegas[i] = omegas[indices[i]]
	}
	expected := GetLagAtSlow(tau, expectedOmegas)
	actual := GetLagAt(uint64(n), tau, indices)

	for i := 0; i < len(expected); i++ {
		if !actual[i].Equal(&expected[i]) {
			t.Errorf("%d: Expected %s, got %s", i, expected[i].String(), actual[i].String())
		}
	}
}

func TestGetLagAt0(t *testing.T) {
	n := 12

	dom := fft.NewDomain(uint64(n))
	omega := dom.Generator
	omegas := make([]fr.Element, n)
	omegas[0] = fr.One()
	for i := 1; i < n; i++ {
		omegas[i].Mul(&omega, &omegas[i-1])
	}

	indices := []int{1, 5, 7, 9, 11}

	expectedOmegas := make([]fr.Element, len(indices))
	for i := 0; i < len(indices); i++ {
		expectedOmegas[i] = omegas[indices[i]]
	}
	expected := GetLagAtSlow(fr.NewElement(0), expectedOmegas)
	actual := GetLagAt0(uint64(n), indices)

	for i := 0; i < len(expected); i++ {
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

func BenchmarkGetLagAt(b *testing.B) {
	var at fr.Element
	for _, n := range []uint64{128, 256, 512, 1024, 2048, 4096, 16384, 32768} {
		omega := fft.NewDomain(n).Generator
		omegas := make([]fr.Element, n)
		omegas[0] = fr.One()
		for i := 1; i < int(n); i++ {
			omegas[i].Mul(&omega, &omegas[i-1])
		}
		at.SetRandom()
		indices := GetRangeTo(int(n))
		omegasAtIndices := make([]fr.Element, len(indices))
		for i := 0; i < len(indices); i++ {
			omegasAtIndices[i] = omegas[indices[i]]
		}
		b.Run(fmt.Sprintf("GetLagAtSlow/%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				GetLagAtSlow(at, omegasAtIndices)
			}
		})
		// b.Run(fmt.Sprintf("GetLagAtNoOmegas/%d", n), func(b *testing.B) {
		// 	for i := 0; i < b.N; i++ {
		// 		GetLagAtNoOmegas(n, at, indices)
		// 	}
		// })
		allOmegas := RootsOfUnity(n)
		b.Run(fmt.Sprintf("GetLagAt/%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				GetLagAtWithOmegas(allOmegas, at, indices)
			}
		})
		b.Run(fmt.Sprintf("GetLagAt0/%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				GetLagAt0WithOmegas(allOmegas, indices)
			}
		})
			for i := 0; i < b.N; i++ {
				GetLagAtWithOmegas(allOmegas, fr.NewElement(0), indices)
			}
		})
	}
}

func newElem(x int64) (z fr.Element) {
	z.SetInt64(x)
	return
}
