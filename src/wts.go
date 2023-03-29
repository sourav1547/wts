package wts

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	// "github.com/consensys/gnark/internal/utils"
)

type Party struct {
	weight  int
	sKey    fr.Element
	pKey    bls.G1Jac
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
	wTau  bls.G2Affine     // com(weights)
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
	var (
		g1InvAff bls.G1Affine
		tau      fr.Element
		g2Tau    bls.G2Affine
	)

	g1, g2, g1a, g2a := bls.Generators()
	g1InvAff.ScalarMultiplication(&g1a, big.NewInt(int64(-1)))

	tau.SetRandom()
	g2Tau.ScalarMultiplication(&g2a, tau.BigInt(&big.Int{}))

	domain := fft.NewDomain(uint64(n))
	omH := domain.Generator
	H := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		H[i].Exp(omH, big.NewInt(int64(i)))
	}

	var coset, coExp fr.Element
	one := fr.One()
	for i := 2; i < n+2; i++ {
		coset = fr.NewElement(uint64(i))
		coExp.Exp(coset, big.NewInt(int64(n)))
		if coExp.Equal(&one) {
			break
		}
	}
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
	var vHTau bls.G2Affine
	var tauN fr.Element
	tauN.Exp(tau, big.NewInt(int64(n)))
	tauN.Sub(&tauN, &one)
	vHTau.ScalarMultiplication(&g2a, tauN.BigInt(&big.Int{}))

	// Computing Lagrange in the exponent
	lagH := GetLagAt(tau, H)
	lagL := GetLagAt(tau, L)
	lagHTaus := bls.BatchScalarMultiplicationG1(&g1a, lagH)
	lag2HTaus := bls.BatchScalarMultiplicationG2(&g2a, lagH)
	lagLTaus := bls.BatchScalarMultiplicationG1(&g1a, lagL)

	// Computing g^alpha
	var (
		alpha  fr.Element
		div    fr.Element
		gAlpha bls.G1Affine
	)
	for i := 0; i < n; i++ {
		alpha.Add(&alpha, div.Div(&lagH[i], &H[i]))
	}
	gAlpha.ScalarMultiplication(&g1a, alpha.BigInt(&big.Int{}))

	return CRS{
		g1:        g1,
		g2:        g2,
		g1a:       g1a,
		g2a:       g2a,
		g1InvAff:  g1InvAff,
		domain:    domain,
		H:         H,
		L:         L,
		tau:       tau,
		g2Tau:     g2Tau,
		vHTau:     vHTau,
		PoT:       PoT,
		lagHTaus:  lagHTaus,
		lag2HTaus: lag2HTaus,
		lagLTaus:  lagLTaus,
		gAlpha:    gAlpha,
	}
}

func NewWTS(n int, weights []int, crs CRS) WTS {
	w := WTS{
		n:       n,
		weights: weights,
		crs:     crs,
	}
	w.keyGen()
	w.preProcess()
	return w
}

func (w *WTS) keyGen() {
	parties := make([]Party, w.n)
	pKeys := make([]bls.G1Affine, w.n)
	sKeys := make([]fr.Element, w.n)

	var (
		sk  fr.Element
		pk  bls.G1Jac
		pka bls.G1Affine
	)
	for i := 0; i < w.n; i++ {
		sk.SetRandom()
		pka.ScalarMultiplication(&w.crs.g1a, sk.BigInt(&big.Int{}))
		pk.FromAffine(&pka)
		pKeys[i] = pka
		sKeys[i] = sk

		parties[i] = Party{
			weight:  w.weights[i],
			sKey:    sk,
			pKey:    pk,
			pKeyAff: pka,
		}

	}

	aTaus := bls.BatchScalarMultiplicationG1(&w.crs.gAlpha, sKeys)
	hTaus := make([]bls.G1Affine, w.n)
	lTaus := make([][]bls.G1Affine, w.n)

	var pComm bls.G1Affine
	for i := 0; i < w.n; i++ {
		hTaus[i].ScalarMultiplication(&w.crs.lagHTaus[i], sKeys[i].BigInt(&big.Int{}))
		pComm.Add(&pComm, &hTaus[i])

		lTaus[i] = make([]bls.G1Affine, w.n-1)
		for ii := 0; ii < w.n-1; ii++ {
			lTaus[i][ii].ScalarMultiplication(&w.crs.lagLTaus[ii], sKeys[i].BigInt(&big.Int{}))
		}
	}

	w.pp = Params{
		pKeys: pKeys,
		pComm: pComm,
		hTaus: hTaus,
		lTaus: lTaus,
		aTaus: aTaus,
	}
	w.signers = parties
}

// Compute
func (w *WTS) preProcess() {
	lagLH := make([][]fr.Element, w.n-1)
	zHL := make([]fr.Element, w.n-1)
	one := fr.One()

	for l := 0; l < w.n-1; l++ {
		lagLH[l] = GetLagAt(w.crs.L[l], w.crs.H)

		zHL[l].Exp(w.crs.L[l], big.NewInt(int64(w.n)))
		zHL[l].Sub(&zHL[l], &one)
	}

	lagLs := make([]bls.G1Affine, w.n-1)
	for l := 0; l < w.n-1; l++ {
		bases := make([]bls.G1Affine, w.n)
		for i := 0; i < w.n; i++ {
			bases[i] = w.pp.lTaus[i][l]
		}
		lagLs[l].MultiExp(bases, lagLH[l], ecc.MultiExpConfig{})
	}

	qTaus := make([]bls.G1Affine, w.n)
	bases := make([]bls.G1Affine, w.n-1)
	exps := make([]fr.Element, w.n-1)

	for i := 0; i < w.n; i++ {
		for l := 0; l < w.n-1; l++ {
			bases[l].Sub(&lagLs[l], &w.pp.lTaus[i][l])
			exps[l].Div(&lagLH[l][i], &zHL[l])
		}
		qTaus[i].MultiExp(bases, exps, ecc.MultiExpConfig{})
	}
	w.pp.qTaus = qTaus

	// pre-processing weights
	weightsF := make([]fr.Element, w.n)
	for i := 0; i < w.n; i++ {
		weightsF[i] = fr.NewElement(uint64(w.weights[i]))
	}

	var wTau bls.G2Jac
	var wTauAf bls.G2Affine
	wTau.MultiExp(w.crs.lag2HTaus, weightsF, ecc.MultiExpConfig{})
	wTauAf.FromJacobian(&wTau)

	w.pp.wTau = wTauAf
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

	var rTau bls.G1Jac
	var rTauAf bls.G1Affine
	rTau.MultiExp(w.crs.lagHTaus, rF, ecc.MultiExpConfig{})
	rTauAf.FromJacobian(&rTau)

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

	var qTau, qrTau bls.G1Jac
	var qTauAf, qrTauAf bls.G1Affine

	qTau.MultiExp(w.crs.PoT, bF, ecc.MultiExpConfig{})
	qrTau.MultiExp(w.crs.PoT[:w.n-1], rF[1:], ecc.MultiExpConfig{})

	qTauAf.FromJacobian(&qTau)
	qrTauAf.FromJacobian(&qrTau)

	return qTauAf, qrTauAf
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

	var (
		qTau   bls.G1Jac
		qTauAf bls.G1Affine
	)
	qTau.MultiExp(w.crs.PoT, bF, ecc.MultiExpConfig{})
	qTauAf.FromJacobian(&qTau)

	return qTauAf
}

// Takes the singing party and signs the message
func (w *WTS) psign(msg Message, signer Party) bls.G2Jac {
	var (
		dst      []byte
		sigma    bls.G2Jac
		roMsgJac bls.G2Jac
	)
	roMsg, _ := bls.HashToG2(msg, dst)
	roMsgJac.FromAffine(&roMsg)

	sigma.ScalarMultiplication(&roMsgJac, signer.sKey.BigInt(&big.Int{}))
	return sigma
}

// Takes the signing key and signs the message
func (w *WTS) pverify(roMsg bls.G2Affine, sigma bls.G2Jac, vk bls.G1Affine) bool {
	var sigmaAff bls.G2Affine
	sigmaAff.FromJacobian(&sigma)

	P := []bls.G1Affine{vk, w.crs.g1InvAff}
	Q := []bls.G2Affine{roMsg, sigmaAff}

	res, err := bls.PairingCheck(P, Q)
	if err != nil {
		fmt.Println("Panic mts verification failed")
	}
	return res
}

// The combine function
func (w *WTS) combine(signers []int, sigmas []bls.G2Jac) Sig {
	var (
		bTau    bls.G1Affine
		bNegTau bls.G2Affine
		qTau    bls.G1Affine
		aggPk   bls.G1Affine
	)
	weight := 0
	for _, idx := range signers {
		bTau.Add(&bTau, &w.crs.lagHTaus[idx])
		bNegTau.Add(&bNegTau, &w.crs.lag2HTaus[idx])
		qTau.Add(&qTau, &w.pp.qTaus[idx])
		aggPk.Add(&aggPk, &w.pp.pKeys[idx])
		weight += w.weights[idx]
	}
	bNegTau.Sub(&w.crs.g2a, &bNegTau)

	// Compute qrTau and checking its correctness
	var (
		qrTau1 bls.G1Affine
		qrTau2 bls.G1Affine
		qrTau  bls.G1Affine
	)

	// Computing the second term
	lagH0 := GetLagAt(fr.NewElement(uint64(0)), w.crs.H)
	var temp bls.G1Affine
	for _, idx := range signers {
		temp.ScalarMultiplication(&w.pp.aTaus[idx], lagH0[idx].BigInt(&big.Int{}))
		qrTau2.Add(&qrTau2, &temp)
	}

	// Computing the first term
	var omHIInv fr.Element
	for _, idx := range signers {
		omHIInv.Inverse(&w.crs.H[idx])
		temp.ScalarMultiplication(&w.pp.hTaus[idx], omHIInv.BigInt(&big.Int{}))
		qrTau1.Add(&qrTau1, &temp)
	}
	qrTau.Sub(&qrTau1, &qrTau2)

	// Aggregating the signature
	var aggSig bls.G2Jac
	for _, sig := range sigmas {
		aggSig.AddAssign(&sig)
	}

	pfP := IPAProof{
		qTau:  qTau,
		qrTau: qrTau,
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
		bTau:    bTau,
		bNegTau: bNegTau,
		aggSig:  aggSig,
		aggPk:   aggPk,
	}
}

// WTS global verify
func (w *WTS) gverify(msg Message, sigma Sig, ths int) bool {

	// 1. Checking aggregated signature is correct
	var sigAff bls.G2Affine
	roMsg, _ := bls.HashToG2(msg, []byte{})
	sigAff.FromJacobian(&sigma.aggSig)

	P := []bls.G1Affine{sigma.aggPk, w.crs.g1InvAff}
	Q := []bls.G2Affine{roMsg, sigAff}
	res, _ := bls.PairingCheck(P, Q)

	pfP := sigma.pi[0]
	pfB := sigma.pi[1]
	pfW := sigma.pi[2]

	// Computing g^{1/n}
	var gNInv bls.G2Affine
	nInv := fr.NewElement(uint64(w.n))
	nInv.Inverse(&nInv)
	gNInv.ScalarMultiplication(&w.crs.g2a, nInv.BigInt(&big.Int{}))

	// Checking the binary relation
	lhs, _ := bls.Pair([]bls.G1Affine{sigma.bTau}, []bls.G2Affine{sigma.bNegTau})
	rhs, _ := bls.Pair([]bls.G1Affine{pfB.qTau}, []bls.G2Affine{w.crs.vHTau})
	res = res && lhs.Equal(&rhs)

	var gThs bls.G1Affine
	gThs.ScalarMultiplication(&w.crs.g1a, big.NewInt(int64(sigma.ths)))
	lhs, _ = bls.Pair([]bls.G1Affine{sigma.bTau}, []bls.G2Affine{w.pp.wTau})
	rhs, _ = bls.Pair([]bls.G1Affine{pfW.qTau, pfW.qrTau, gThs}, []bls.G2Affine{w.crs.vHTau, w.crs.g2Tau, gNInv})

	// 2 Checking aggP, i.e., s(tau)b(tau) = q(tau)z(tau) + tau q_r(tau) + aggPk/n
	var b2Tau bls.G2Affine
	b2Tau.Sub(&w.crs.g2a, &sigma.bNegTau)
	lhs, _ = bls.Pair([]bls.G1Affine{w.pp.pComm}, []bls.G2Affine{b2Tau})
	rhs, _ = bls.Pair([]bls.G1Affine{pfP.qTau, pfP.qrTau, sigma.aggPk}, []bls.G2Affine{w.crs.vHTau, w.crs.g2Tau, gNInv})
	res = res && lhs.Equal(&rhs)

	return res && (ths <= sigma.ths)
}
