package wts

import (
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
)

type Party struct {
	weight  int
	sKey    fr.Element
	pKeyAff bls.G1Affine
}

type IPAProof struct {
	qTau  bls.G1Affine
	qrTau bls.G1Affine
}

type Sig struct {
	bTau    bls.G1Affine // Commitment to the bitvector
	bNegTau bls.G2Affine // Commitment to the bitvector in G2
	ths     int          // Threshold
	pi      []IPAProof   // IPA proofs
	aggPk   bls.G1Affine // Aggregated public key
	aggSig  bls.G2Jac    // Aggregated signature
}

type CRS struct {
	// Generators
	g1       bls.G1Jac
	g2       bls.G2Jac
	g1a      bls.G1Affine
	g2a      bls.G2Affine
	g1InvAff bls.G1Affine
	// Lagrange polynomials
	tau       fr.Element // FIXME: To remove, only added for testing purposes
	domain    *fft.Domain
	H         []fr.Element
	L         []fr.Element
	lagLH     [][]fr.Element
	zHLInv    fr.Element
	g2Tau     bls.G2Affine
	vHTau     bls.G2Affine
	PoT       []bls.G1Affine
	lagHTaus  []bls.G1Affine // [Lag_i(tau)]
	lag2HTaus []bls.G2Affine // [g2^Lag_i(tau)]
	lagLTaus  []bls.G1Affine // [Lag_l(tau)]
	gAlpha    bls.G1Affine   // h_alpha
}

type Params struct {
	pComm bls.G1Affine     // com(g^s_i)
	wTau  bls.G1Affine     // com(weights)
	pKeys []bls.G1Affine   // [g^s_i]
	qTaus []bls.G1Affine   // [h^{s_i.q_i(tau)}]
	hTaus []bls.G1Affine   // [h^{s_i.Lag_i(tau)}]
	lTaus [][]bls.G1Affine // [h^{s_i.Lag_l(tau)}]
	aTaus []bls.G1Affine   // [h_alpha^{s_i}]
	// Pre-processing weights
	wqTaus  []bls.G1Affine
	wqrTaus []bls.G1Affine
}

type WTS struct {
	weights []int   // Weight distribution
	n       int     // Total number of signers
	signers []Party // List of signers
	crs     CRS     // CRS for the protocol
	pp      Params  // The parameters for the signatures
}

func GenCRS(n int) CRS {
	g1, g2, g1a, g2a := bls.Generators()

	var tau fr.Element
	tau.SetRandom()
	g2Tau := new(bls.G2Jac).ScalarMultiplication(&g2, tau.BigInt(&big.Int{}))

	domain := fft.NewDomain(uint64(n))
	omH := domain.Generator
	H := make([]fr.Element, n)
	H[0].SetOne()
	for i := 1; i < n; i++ {
		H[i].Mul(&omH, &H[i-1])
	}

	// OPT: Can we work with a better coset?
	one := fr.One()
	var coset, coExp fr.Element
	for i := 2; i < n+2; i++ {
		coset = fr.NewElement(uint64(i))
		coExp.Exp(coset, big.NewInt(int64(n)))
		if !coExp.Equal(&one) {
			break
		}
	}
	coExp.Sub(&coExp, &one)
	coExp.Inverse(&coExp)

	L := make([]fr.Element, n-1)
	for i := 0; i < n-1; i++ {
		L[i].Mul(&coset, &H[i])
	}

	poT := make([]fr.Element, n)
	poT[0].SetOne()
	for i := 1; i < n; i++ {
		poT[i].Mul(&poT[i-1], &tau)
	}
	PoT := bls.BatchScalarMultiplicationG1(&g1a, poT)

	// Computing vHTau
	var tauN fr.Element
	tauN.Exp(tau, big.NewInt(int64(n)))
	tauN.Sub(&tauN, &one)
	vHTau := new(bls.G2Jac).ScalarMultiplication(&g2, tauN.BigInt(&big.Int{}))

	// Computing Lagrange in the exponent
	// OPT: Current implementation of GetLagAt is quadratic, we can make it O(nlogn)
	lagH := GetLagAt(tau, H)
	lagL := GetLagAt(tau, L) // OPT: Can we reuse the denominators from GetLag(tau,H)?
	lagHTaus := bls.BatchScalarMultiplicationG1(&g1a, lagH)
	lag2HTaus := bls.BatchScalarMultiplicationG2(&g2a, lagH)
	lagLTaus := bls.BatchScalarMultiplicationG1(&g1a, lagL)

	// Computing g^alpha
	var alpha, div fr.Element
	for i := 0; i < n; i++ {
		alpha.Add(&alpha, div.Div(&lagH[i], &H[i]))
	}
	gAlpha := new(bls.G1Jac).ScalarMultiplication(&g1, alpha.BigInt(&big.Int{}))

	lagLH := GetBatchLag(L, H)

	return CRS{
		g1:        g1,
		g2:        g2,
		g1a:       g1a,
		g2a:       g2a,
		g1InvAff:  *new(bls.G1Affine).FromJacobian(new(bls.G1Jac).Neg(&g1)),
		domain:    domain,
		H:         H,
		L:         L,
		lagLH:     lagLH,
		zHLInv:    coExp,
		tau:       tau,
		g2Tau:     *new(bls.G2Affine).FromJacobian(g2Tau),
		vHTau:     *new(bls.G2Affine).FromJacobian(vHTau),
		PoT:       PoT,
		lagHTaus:  lagHTaus,
		lag2HTaus: lag2HTaus,
		lagLTaus:  lagLTaus,
		gAlpha:    *new(bls.G1Affine).FromJacobian(gAlpha),
	}
}

func NewWTS(n int, weights []int, crs CRS) WTS {
	w := WTS{
		n:       n,
		weights: weights,
		crs:     crs,
	}
	w.keyGen()
	return w
}

// Only to be used for benchmarking per signer key generation
func (w *WTS) keyGenBench() {
	var sKey fr.Element
	var pKey bls.G1Jac
	var aTau, hTau bls.G1Affine

	sKey.SetRandom()
	skInt := sKey.BigInt(&big.Int{})

	var wg sync.WaitGroup
	wg.Add(w.n - 1)
	lTaus := make([]bls.G1Affine, w.n)
	for i := 0; i < w.n-1; i++ {
		go func(i int) {
			defer wg.Done()
			lTaus[i].ScalarMultiplication(&w.crs.lagLTaus[i], skInt)
		}(i)
	}

	// TODO: work with Jacobian in all these cases
	pKey.ScalarMultiplication(&w.crs.g1, skInt)
	aTau.ScalarMultiplication(&w.crs.gAlpha, skInt)
	hTau.ScalarMultiplication(&w.crs.lagHTaus[0], skInt)

	wg.Wait()
}

// This is the keyGen function we use in the paper.
func (w *WTS) keyGen() {
	parties := make([]Party, w.n)
	sKeys := make([]fr.Element, w.n)

	for i := 0; i < w.n; i++ {
		sKeys[i].SetRandom()
	}
	pKeys := bls.BatchScalarMultiplicationG1(&w.crs.g1a, sKeys)

	var wg sync.WaitGroup
	wg.Add(w.n - 1)
	lTaus := make([][]bls.G1Affine, w.n)
	for i := 0; i < w.n-1; i++ {
		go func(i int) {
			defer wg.Done()
			lTaus[i] = bls.BatchScalarMultiplicationG1(&w.crs.lagLTaus[i], sKeys)
		}(i)
	}

	for i := 0; i < w.n; i++ {
		parties[i] = Party{
			weight:  w.weights[i],
			sKey:    sKeys[i],
			pKeyAff: pKeys[i],
		}
	}

	aTaus := bls.BatchScalarMultiplicationG1(&w.crs.gAlpha, sKeys)
	hTaus := make([]bls.G1Jac, w.n)

	var pComm, lagHTau bls.G1Jac
	for i := 0; i < w.n; i++ {
		lagHTau.FromAffine(&w.crs.lagHTaus[i])
		hTaus[i].ScalarMultiplication(&lagHTau, sKeys[i].BigInt(&big.Int{}))
		pComm.AddAssign(&hTaus[i])
	}

	wg.Wait()

	w.pp = Params{
		pKeys: pKeys,
		pComm: *new(bls.G1Affine).FromJacobian(&pComm),
		hTaus: bls.BatchJacobianToAffineG1(hTaus),
		lTaus: lTaus,
		aTaus: aTaus,
	}
	w.signers = parties
}

func (w *WTS) preProcess() {
	lagLs := make([]bls.G1Jac, w.n-1)
	var wg1 sync.WaitGroup
	wg1.Add(w.n - 1)
	for l := 0; l < w.n-1; l++ {
		go func(l int) {
			defer wg1.Done()
			lagLs[l].MultiExp(w.pp.lTaus[l], w.crs.lagLH[l], ecc.MultiExpConfig{})
		}(l)
	}
	wg1.Wait()

	var lTau bls.G1Jac
	exps := make([]fr.Element, w.n-1)
	bases := make([]bls.G1Jac, w.n-1)
	qTaus := make([]bls.G1Jac, w.n)
	for i := 0; i < w.n; i++ {
		for l := 0; l < w.n-1; l++ {
			lTau.FromAffine(&w.pp.lTaus[l][i])
			bases[l] = lagLs[l]
			bases[l].SubAssign(&lTau)
			exps[l].Mul(&w.crs.lagLH[l][i], &w.crs.zHLInv) // Can also be pushed to Setup
		}
		qTaus[i].MultiExp(bls.BatchJacobianToAffineG1(bases), exps, ecc.MultiExpConfig{})
	}
	w.pp.qTaus = bls.BatchJacobianToAffineG1(qTaus)

	// pre-processing weights
	weightsF := make([]fr.Element, w.n)
	for i := 0; i < w.n; i++ {
		weightsF[i] = fr.NewElement(uint64(w.weights[i]))
	}

	wTau, _ := new(bls.G1Jac).MultiExp(w.crs.lagHTaus, weightsF, ecc.MultiExpConfig{})
	w.pp.wTau = *new(bls.G1Affine).FromJacobian(wTau)
}

func (w *WTS) weightsPf(signers []int) (bls.G1Affine, bls.G1Affine) {
	bF := make([]fr.Element, w.n)
	wF := make([]fr.Element, w.n)
	rF := make([]fr.Element, w.n)

	for i := 0; i < w.n; i++ {
		wF[i] = fr.NewElement(uint64(w.weights[i]))
	}
	for _, idx := range signers {
		bF[idx] = fr.One()
		rF[idx] = wF[idx]
	}

	w.crs.domain.FFTInverse(bF, fft.DIF)
	w.crs.domain.FFTInverse(wF, fft.DIF)
	w.crs.domain.FFTInverse(rF, fft.DIF)

	w.crs.domain.FFT(bF, fft.DIT, true)
	w.crs.domain.FFT(wF, fft.DIT, true)
	w.crs.domain.FFT(rF, fft.DIT, true)

	one := fr.One()
	var den fr.Element
	den.Exp(w.crs.domain.FrMultiplicativeGen, big.NewInt(int64(w.crs.domain.Cardinality)))
	den.Sub(&den, &one).Inverse(&den)

	for i := 0; i < w.n; i++ {
		bF[i].Mul(&bF[i], &wF[i]).
			Sub(&bF[i], &rF[i]).
			Mul(&bF[i], &den)
	}
	w.crs.domain.FFTInverse(bF, fft.DIF, true)
	w.crs.domain.FFTInverse(rF, fft.DIF, true)
	fft.BitReverse(bF)
	fft.BitReverse(rF)

	qTau, _ := new(bls.G1Jac).MultiExp(w.crs.PoT, bF, ecc.MultiExpConfig{})
	qrTau, _ := new(bls.G1Jac).MultiExp(w.crs.PoT[:w.n-1], rF[1:], ecc.MultiExpConfig{})

	return *new(bls.G1Affine).FromJacobian(qTau), *new(bls.G1Affine).FromJacobian(qrTau)
}

func (w *WTS) binaryPf(signers []int) bls.G1Affine {
	one := fr.One()
	bF := make([]fr.Element, w.n)
	bNegF := make([]fr.Element, w.n)

	for i := 0; i < w.n; i++ {
		bNegF[i] = fr.One()
	}
	for _, idx := range signers {
		bF[idx] = fr.One()
		bNegF[idx].SetZero()
	}

	w.crs.domain.FFTInverse(bF, fft.DIF)
	w.crs.domain.FFTInverse(bNegF, fft.DIF)

	w.crs.domain.FFT(bF, fft.DIT, true)
	w.crs.domain.FFT(bNegF, fft.DIT, true)

	var den fr.Element
	den.Exp(w.crs.domain.FrMultiplicativeGen, big.NewInt(int64(w.crs.domain.Cardinality)))
	den.Sub(&den, &one).Inverse(&den)

	for i := 0; i < w.n; i++ {
		bF[i].Mul(&bF[i], &bNegF[i]).
			Mul(&bF[i], &den)
	}
	w.crs.domain.FFTInverse(bF, fft.DIF, true)
	fft.BitReverse(bF)

	qTau, _ := new(bls.G1Jac).MultiExp(w.crs.PoT, bF, ecc.MultiExpConfig{})
	return *new(bls.G1Affine).FromJacobian(qTau)
}

// Takes the singing party and signs the message
func (w *WTS) psign(msg Message, signer Party) bls.G2Jac {
	roMsg, _ := bls.HashToG2(msg, []byte{})

	return *new(bls.G2Jac).ScalarMultiplication(new(bls.G2Jac).FromAffine(&roMsg), signer.sKey.BigInt(&big.Int{}))
}

// Takes the signing key and signs the message
func (w *WTS) pverify(roMsg bls.G2Affine, sigma bls.G2Jac, vk bls.G1Affine) bool {
	res, _ := bls.PairingCheck([]bls.G1Affine{vk, w.crs.g1InvAff}, []bls.G2Affine{roMsg, *new(bls.G2Affine).FromJacobian(&sigma)})
	return res
}

// The combine function
func (w *WTS) combine(signers []int, sigmas []bls.G2Jac) Sig {
	var bTau, qTau, aggPk bls.G1Jac
	var b2Tau bls.G2Jac

	weight := 0
	for _, idx := range signers {
		bTau.AddMixed(&w.crs.lagHTaus[idx])
		b2Tau.AddMixed(&w.crs.lag2HTaus[idx])
		qTau.AddMixed(&w.pp.qTaus[idx])
		aggPk.AddMixed(&w.pp.pKeys[idx])
		weight += w.weights[idx]
	}
	bNegTau := w.crs.g2
	bNegTau.SubAssign(&b2Tau)

	// Compute qrTau and checking its correctness
	var qrTau, qrTau2 bls.G1Jac
	t := len(signers)
	bases := make([]bls.G1Affine, t)
	expts := make([]fr.Element, t)

	// Computing the second term
	// OPT: Can possibly optimize this
	// OPT: Can also send the indices of the signers while computing lagH0
	lagH0 := GetLagAt(fr.NewElement(uint64(0)), w.crs.H)
	for i, idx := range signers {
		expts[i] = lagH0[idx]
		bases[i] = w.pp.aTaus[idx]
	}
	qrTau2.MultiExp(bases, expts, ecc.MultiExpConfig{})

	// Computing the first term
	for i, idx := range signers {
		expts[i].Inverse(&w.crs.H[idx])
		bases[i] = w.pp.hTaus[idx]
	}
	qrTau.MultiExp(bases, expts, ecc.MultiExpConfig{})

	// first term - second term
	qrTau.SubAssign(&qrTau2)

	// Aggregating the signature
	var aggSig bls.G2Jac
	for _, sig := range sigmas {
		aggSig.AddAssign(&sig)
	}

	pfP := IPAProof{
		qTau:  *new(bls.G1Affine).FromJacobian(&qTau),
		qrTau: *new(bls.G1Affine).FromJacobian(&qrTau),
	}

	pfB := IPAProof{
		qTau: w.binaryPf(signers),
	}

	qwTau, qrwTau := w.weightsPf(signers)
	pfW := IPAProof{
		qTau:  qwTau,
		qrTau: qrwTau,
	}

	return Sig{
		pi:      []IPAProof{pfP, pfB, pfW},
		ths:     weight,
		bTau:    *new(bls.G1Affine).FromJacobian(&bTau),
		bNegTau: *new(bls.G2Affine).FromJacobian(&bNegTau),
		aggSig:  aggSig,
		aggPk:   *new(bls.G1Affine).FromJacobian(&aggPk),
	}
}

// WTS global verify
func (w *WTS) gverify(msg Message, sigma Sig, ths int) bool {

	// 1. Checking aggregated signature is correct
	roMsg, _ := bls.HashToG2(msg, []byte{})
	res, _ := bls.PairingCheck([]bls.G1Affine{sigma.aggPk, w.crs.g1InvAff}, []bls.G2Affine{roMsg, *new(bls.G2Affine).FromJacobian(&sigma.aggSig)})

	pfP := sigma.pi[0]
	pfB := sigma.pi[1]
	pfW := sigma.pi[2]

	// Computing g^{1/n}
	// TODO: Can pre-process it
	nInv := fr.NewElement(uint64(w.n))
	nInv.Inverse(&nInv)
	gNInv := *new(bls.G2Affine).FromJacobian(new(bls.G2Jac).ScalarMultiplication(&w.crs.g2, nInv.BigInt(&big.Int{})))

	// Checking the binary relation
	lhs, _ := bls.Pair([]bls.G1Affine{sigma.bTau}, []bls.G2Affine{sigma.bNegTau})
	rhs, _ := bls.Pair([]bls.G1Affine{pfB.qTau}, []bls.G2Affine{w.crs.vHTau})
	res = res && lhs.Equal(&rhs)

	var b2Tau bls.G2Affine
	b2Tau.Sub(&w.crs.g2a, &sigma.bNegTau)

	gThs := *new(bls.G1Affine).FromJacobian(new(bls.G1Jac).ScalarMultiplication(&w.crs.g1, big.NewInt(int64(sigma.ths))))
	lhs, _ = bls.Pair([]bls.G1Affine{w.pp.wTau}, []bls.G2Affine{b2Tau})
	rhs, _ = bls.Pair([]bls.G1Affine{pfW.qTau, pfW.qrTau, gThs}, []bls.G2Affine{w.crs.vHTau, w.crs.g2Tau, gNInv})
	res = res && lhs.Equal(&rhs)

	// 2 Checking aggP, i.e., s(tau)b(tau) = q(tau)z(tau) + tau q_r(tau) + aggPk/n

	lhs, _ = bls.Pair([]bls.G1Affine{w.pp.pComm}, []bls.G2Affine{b2Tau})
	rhs, _ = bls.Pair([]bls.G1Affine{pfP.qTau, pfP.qrTau, sigma.aggPk}, []bls.G2Affine{w.crs.vHTau, w.crs.g2Tau, gNInv})
	res = res && lhs.Equal(&rhs)

	return res && (ths <= sigma.ths)
}
