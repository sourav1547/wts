package wts

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"golang.org/x/exp/constraints"
)

var (
	zeros   []fr.Element
	domains = make(map[uint64]*fft.Domain)
)

type Message []byte

// This function returns the lagrange coefficients for a given set of indices when evaluated at a specific point
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


func GetLagAt(N uint64, at fr.Element, indices []int) []fr.Element {
	return GetLagAtWithOmegas(RootsOfUnity(N), at, indices)
}

// This function returns the lagrange coefficients for a given set of indices when evaluated at a specific point
func GetLagAtWithOmegas(omegas []fr.Element, at fr.Element, indices []int) []fr.Element {
	N := len(omegas)
	n := len(indices)

	// Z(X) = \prod_{i in T} (X - \omega^i)
	roots := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		roots[i] = omegas[indices[i]]
	}
	Z := GetCoefficientsFromRoots(roots)
	// Z(at)
	Zat := EvaluatePoly(Z, at)

	// rootsAt = (at - \omega^i)
	for i := 0; i < n; i++ {
		roots[i].Sub(&at, &roots[i])
	}
	// Batch inversion for 1/(at - \omega^i)
	roots = fr.BatchInvert(roots)

	// Set Z as Z'(X)
	Differentiate(&Z)

	dom := GetDomain(uint64(N))
	Z = append(Z, GetZeros(dom.Cardinality-uint64(len(Z)))...)
	fft.BitReverse(Z)
	// Z'(\omega^i) for i..N
	dom.FFT(Z, fft.DIT)

	// denominatorsInv = Z'(\omega^i)
	denominators := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		denominators[i] = Z[indices[i]]
	}
	// Batch inversion for 1/Z'(\omega^i)
	denominators = fr.BatchInvert(denominators)

	for i := 0; i < n; i++ {
		// numerator = Z(at)/(at - \omega^i)
		roots[i].Mul(&Zat, &roots[i])
		Z[i].Mul(&roots[i], &denominators[i])
	}

	return Z[:n]
}

func GetLagAt0(N uint64, indices []int) []fr.Element {
	return GetLagAt0WithOmegas(RootsOfUnity(N), indices)
}

func GetLagAt0WithOmegas(omegas []fr.Element, indices []int) []fr.Element {
	N := len(omegas)
	n := len(indices)

	// Z(X) = \prod_{i in T} (X - \omega^i)
	roots := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		roots[i] = omegas[indices[i]]
	}
	Z := GetCoefficientsFromRoots(roots)
	// rootsAt0 = 1/-\omega^i
	for i, idx := range indices {
		/*
		* Recall that:
		*  a) Inverses can be computed fast as: (\omega^k)^{-1} = \omega^{-k} = \omega^N \omega^{-k} = \omega^{N-k}
		*  b) Negations can be computed fast as: -\omega^k = \omega^{k + N/2}
		*
		* So, (0 - \omega^i)^{-1} = (\omega^{i + N/2})^{-1} = \omega^{N - (i + N/2)} = \omega^{N/2 - i}
		* If N/2 < i, then you wrap around to N + N/2 - i.
		 */
		if N/2 < idx {
			idx = N + N/2 - idx
		} else {
			idx = N/2 - idx
		}
		roots[i].Mul(&Z[0], &omegas[idx])
	}

	// Set Z as Z'(X)
	Differentiate(&Z)

	dom := GetDomain(uint64(len(omegas)))
	Z = append(Z, GetZeros(dom.Cardinality-uint64(len(Z)))...)
	fft.BitReverse(Z)
	// Z'(\omega^i) for i..N
	dom.FFT(Z, fft.DIT)

	// denominatorsInv = Z'(\omega^i)
	denominators := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		denominators[i] = Z[indices[i]]
	}
	// Batch inversion for 1/Z'(\omega^i)
	denominators = fr.BatchInvert(denominators)

	for i := 0; i < n; i++ {
		Z[i].Mul(&roots[i], &denominators[i])
	}

	return Z[:n]
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

// This function returns the roots of unity up to the next power of 2
func RootsOfUnity(n uint64) []fr.Element {
	dom := GetDomain(n)
	N := dom.Cardinality
	omegas := make([]fr.Element, N)
	// top level of twiddle factors contains N/2 roots of unity
	// so copy those in and fill in rest
	for i := uint64(copy(omegas, dom.Twiddles[0])); i < N; i++ {
		omegas[i].Mul(&omegas[i-1], &dom.Generator)
	}
	return omegas
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
	dom := GetDomain(uint64(len(left) + len(right) - 1))
	n := dom.Cardinality
	left = append(left, GetZeros(n-uint64(len(left)))...)
	right = append(right, GetZeros(n-uint64(len(right)))...)
	dom.FFT(left, fft.DIF)
	dom.FFT(right, fft.DIF)
	for i := uint64(0); i < n; i++ {
		left[i].Mul(&left[i], &right[i])
	}
	dom.FFTInverse(left, fft.DIT)
	// truncate zeros
	for left[n-1].IsZero() {
		n--
	}
	return left[:n]
}

func EvaluatePoly(pol []fr.Element, val fr.Element) fr.Element {
	var acc, res, tmp fr.Element
	res.Set(&pol[0])
	acc.Set(&val)
	for i := 1; i < len(pol); i++ {
		tmp.Mul(&acc, &pol[i])
		res.Add(&res, &tmp)
		acc.Mul(&acc, &val)
	}
	return res
}

func GetDomain(m uint64) *fft.Domain {
	n := ecc.NextPowerOfTwo(uint64(m))
	if dom, ok := domains[n]; ok {
		return dom
	}
	dom := fft.NewDomain(n)
	domains[n] = dom
	return dom
}

func GetRange[T constraints.Integer](from, to T) []T {
	res := make([]T, 0, to-from)
	for ; from < to; from++ {
		res = append(res, from)
	}
	return res
}

func GetRangeTo[T constraints.Integer](to T) []T {
	return GetRange(0, to)
}

func GetZeros(n uint64) []fr.Element {
	if n < uint64(len(zeros)) {
		return zeros[:n]
	}
	for uint64(len(zeros)) < n {
		zeros = append(zeros, fr.NewElement(0))
	}
	return zeros[:n]
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

// func SubDomain(dom *fft.Domain, m int) *fft.Domain {
// 	N := dom.Cardinality
// 	n := ecc.NextPowerOfTwo(uint64(m))
// 	if n > N {
// 		panic("m is too large")
// 	}
// 	if n == N {
// 		return dom
// 	}
// 	// https://dsp.stackexchange.com/questions/73367/understanding-the-twiddle-factors
// 	nbStages := uint64(bits.TrailingZeros64(n))
// 	twiddles := make([][]fr.Element, nbStages)
// 	twiddlesInv := make([][]fr.Element, nbStages)
// 	factorBigger := int(N / n)
// 	for i := uint64(0); i < nbStages; i++ {
// 		twiddles[i] = make([]fr.Element, 0, 1+(1<<(nbStages-i-1)))
// 		twiddlesInv[i] = make([]fr.Element, 0, 1+(1<<(nbStages-i-1)))
// 		for j := 0; j < len(dom.Twiddles[i]); j += factorBigger {
// 			twiddles[i] = append(twiddles[i], dom.Twiddles[i][j])
// 			twiddlesInv[i] = append(twiddlesInv[i], dom.TwiddlesInv[i][j])
// 		}
// 	}
// 	return &fft.Domain{
// 		Cardinality:            n,
// 		CardinalityInv:         dom.CardinalityInv,
// 		Generator:              dom.Generator,
// 		GeneratorInv:           dom.GeneratorInv,
// 		FrMultiplicativeGen:    dom.FrMultiplicativeGen,
// 		FrMultiplicativeGenInv: dom.FrMultiplicativeGenInv,
// 		CosetTable:             dom.CosetTable[:n],
// 		CosetTableReversed:     dom.CosetTableReversed[:n],
// 		CosetTableInv:          dom.CosetTableInv[:n],
// 		CosetTableInvReversed:  dom.CosetTableInvReversed[:n],
// 		Twiddles:               twiddles,
// 		TwiddlesInv:            twiddlesInv,
// 	}
// }
