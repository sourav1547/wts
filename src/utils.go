package wts

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
)

var (
	Zero = fr.NewElement(0)
)

type Message []byte

// This function returns the lagrange coefficients for a given set of indices when evaluated at a specific point
// TODO: Have to optimize this
func GetLagAtSlow(at fr.Element, indices []fr.Element) []fr.Element {
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

// This function returns the lagrange coefficients for a given set of indices when evaluated at a specific point
func GetLagAt(at fr.Element, T []fr.Element) []fr.Element {
	n := len(T)

	// Z(at) = \prod_{i in T} (at - \omega^i)
	Zat := fr.One()
	div := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		div[i].Sub(&at, &T[i])
		Zat.Mul(&Zat, &div[i])
	}

	// Z(X) = \prod_{i in T} (X - \omega^i)
	Z := GetCoefficientsFromRoots(T)

	// Z'(X) = \sum_{i in T} \prod_{j in T, j != i} (X - \omega^j)
	Differentiate(&Z)

	dom := fft.NewDomain(uint64(n))
	ZPrime := make([]fr.Element, dom.Cardinality)
	for i := uint64(copy(ZPrime, Z)); i < dom.Cardinality; i++ {
		ZPrime[i] = fr.NewElement(0)
	}
	fft.BitReverse(ZPrime)
	dom.FFT(ZPrime, fft.DIT)

	denominators := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		denominators[i] = ZPrime[i]
	}
	denominators = fr.BatchInvert(denominators)
	div = fr.BatchInvert(div)

	var nume fr.Element
	for i := 0; i < n; i++ {
		nume.Mul(&Zat, &div[i])
		ZPrime[i].Mul(&nume, &denominators[i])
	}

	return ZPrime[:n]
}

// This function is not generic. I will use the Prod(x-hi)=x^n-1
func GetBatchLag(L, H []fr.Element) [][]fr.Element {
	nL := len(L)
	nH := len(H)
	lagLH := make([][]fr.Element, nL)
	denos := make([]fr.Element, nH)

	// Compute all the denominators
	var deno, diff fr.Element
	for i := 0; i < nH; i++ {
		deno = fr.One()
		for ii := 0; ii < nH; ii++ {
			if i != ii {
				diff.Sub(&H[i], &H[ii])
				deno.Mul(&deno, &diff)
			}
		}
		denos[i] = deno
	}

	powers := make([]fr.Element, nL)
	var power fr.Element
	one := fr.One()
	for i := 0; i < nL; i++ {
		power.Exp(L[i], big.NewInt(int64(nH)))
		powers[i].Sub(&power, &one)
	}

	for i := 0; i < nL; i++ {
		lagLH[i] = make([]fr.Element, nH)
		for ii := 0; ii < nH; ii++ {
			deno.Sub(&L[i], &H[ii])
			deno.Mul(&deno, &denos[ii])
			lagLH[i][ii].Div(&powers[i], &deno)
		}
	}
	return lagLH
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

// TODO: Optimize further
func GetCoefficientsFromRoots(roots []fr.Element) []fr.Element {
	if len(roots) == 0 {
		return []fr.Element{}
	}
	if len(roots) == 1 {
		// (X - roots[0])
		c := new(fr.Element).Neg(&roots[0])
		return []fr.Element{*c, fr.One()}
	}

	m := len(roots) / 2
	left := GetCoefficientsFromRoots(roots[:m])
	right := GetCoefficientsFromRoots(roots[m:])
	if len(left) == 0 {
		return right
	}
	if len(right) == 0 {
		return left
	}
	return MulPolynomials(left, right)
}

// Differentiate gets the derivative of the polynomial p inplace
func Differentiate(p *[]fr.Element) {
	ps := *p
	n := len(ps) - 1
	for i := 0; i < n; i++ {
		ps[i].Mul(&ps[i+1], new(fr.Element).SetUint64(uint64(i+1)))
	}
	*p = ps[:n]
}

func MulPolynomials(left, right []fr.Element) []fr.Element {
	dom := fft.NewDomain(uint64(len(left) + len(right) - 1))
	n := int(dom.Cardinality)
	lNew := make([]fr.Element, n)
	for i := copy(lNew, left); i < n; i++ {
		lNew[i] = fr.NewElement(0)
	}
	rNew := make([]fr.Element, n)
	for i := copy(rNew, right); i < n; i++ {
		rNew[i] = fr.NewElement(0)
	}

	dom.FFT(lNew, fft.DIF)
	dom.FFT(rNew, fft.DIF)
	for i := 0; i < n; i++ {
		lNew[i].Mul(&lNew[i], &rNew[i])
	}
	dom.FFTInverse(lNew, fft.DIT)
	//? truncate zeros
	// for i := n - 1; i >= 0; i-- {
	// 	if lNew[i].IsZero() {
	// 		lNew = lNew[:i]
	// 	} else {
	// 		break
	// 	}
	// }
	return lNew
}
