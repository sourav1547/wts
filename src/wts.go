package wts

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type Party struct {
	weight  int
	sKey    fr.Element
	pKey    bls.G1Jac
	pKeyAff bls.G1Affine
}

type IPAProof struct {
	qTau  bls.G1Affine
	rTau  bls.G1Affine
	qrTau bls.G1Affine
}

type Sig struct {
	bTau   bls.G2Affine // Commitment to the bitvector
	ths    int          // Threshold
	pi     []IPAProof   // IPA proofs
	aggPk  bls.G1Affine // Aggregated public key
	aggSig bls.G2Jac    // Aggregated signature
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
	H         []fr.Element
	L         []fr.Element
	g2Tau     bls.G2Affine
	vHTau     bls.G2Affine
	lagHTaus  []bls.G1Affine // [Lag_i(tau)]
	lag2HTaus []bls.G2Affine // [g2^Lag_i(tau)]
	lagLTaus  []bls.G1Affine // [Lag_l(tau)]
	gAlpha    bls.G1Affine   // h_alpha
}

type Params struct {
	pComm bls.G1Affine     // com(g^s_i)
	pKeys []bls.G1Affine   // [g^s_i]
	qTaus []bls.G1Affine   // [h^{s_i.q_i(tau)}]
	hTaus []bls.G1Affine   // [h^{s_i.Lag_i(tau)}]
	lTaus [][]bls.G1Affine // [h^{s_i.Lag_l(tau)}]
	aTaus []bls.G1Affine   // [h_alpha^{s_i}]
}

type WTS struct {
	weights []int   // Weight distribution
	n       int     // Total number of signers
	signers []Party // List of signers
	crs     CRS     // CRS for the protocol
	pp      Params  // The parameters for the signatures
}

func GenCRS(n int) CRS {
	omH := GetOmega(n, 0)
	var (
		g1InvAff bls.G1Affine
		tau      fr.Element
		g2Tau    bls.G2Affine
	)

	g1, g2, g1a, g2a := bls.Generators()
	g1InvAff.ScalarMultiplication(&g1a, big.NewInt(int64(-1)))

	tau.SetRandom()
	g2Tau.ScalarMultiplication(&g2a, tau.BigInt(&big.Int{}))

	// Computing H and L
	H := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		H[i].Exp(omH, big.NewInt(int64(i)))
	}

	// FIXME: This is probably not correct
	// Currently L:{2,3,...,n+1}
	L := make([]fr.Element, n-1)
	for i := 0; i < n-1; i++ {
		L[i] = fr.NewElement(uint64(i + 2))
	}

	// TODO: To remove this check after fixing the above issue
	for _, h := range H {
		for _, l := range L {
			if h.Equal(&l) {
				fmt.Println("L and H are not disjoint! PANIC")
			}
		}
	}

	// Computing vHTau
	var vHTau bls.G2Affine
	var tauN fr.Element
	tauN.Exp(tau, big.NewInt(int64(n)))
	one := fr.One()
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
		H:         H,
		L:         L,
		tau:       tau,
		g2Tau:     g2Tau,
		vHTau:     vHTau,
		lagHTaus:  lagHTaus,
		lag2HTaus: lag2HTaus,
		lagLTaus:  lagLTaus,
		gAlpha:    gAlpha,
	}
}

func NewWTS(n, ths int, weights []int, crs CRS) WTS {
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

	for l := 0; l < w.n-1; l++ {
		lagLH[l] = GetLagAt(w.crs.L[l], w.crs.H)

		one := fr.One()
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
	for i := 0; i < w.n; i++ {
		bases := make([]bls.G1Affine, w.n-1)
		exps := make([]fr.Element, w.n-1)

		for l := 0; l < w.n-1; l++ {
			bases[l].Sub(&lagLs[l], &w.pp.lTaus[i][l])
			exps[l].Div(&lagLH[l][i], &zHL[l])
		}
		qTaus[i].MultiExp(bases, exps, ecc.MultiExpConfig{})
	}
	w.pp.qTaus = qTaus
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
		bTau  bls.G2Affine
		qTau  bls.G1Affine
		rTau  bls.G1Affine
		aggPk bls.G1Affine
	)
	weight := 0
	for _, idx := range signers {
		bTau.Add(&bTau, &w.crs.lag2HTaus[idx])
		qTau.Add(&qTau, &w.pp.qTaus[idx])
		rTau.Add(&rTau, &w.pp.hTaus[idx])
		aggPk.Add(&aggPk, &w.pp.pKeys[idx])
		weight += w.weights[idx]
	}

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

	pf1 := IPAProof{
		qTau:  qTau,
		rTau:  rTau,
		qrTau: qrTau,
	}

	return Sig{
		pi:     []IPAProof{pf1},
		ths:    weight,
		bTau:   bTau,
		aggSig: aggSig,
		aggPk:  aggPk,
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

	// 2.1 Checking aggP, i.e., s(tau)b(tau) = q(tau)z(tau) + r(tau)
	aggPi := sigma.pi[0]
	lhs, _ := bls.Pair([]bls.G1Affine{w.pp.pComm}, []bls.G2Affine{sigma.bTau})
	rhs, _ := bls.Pair([]bls.G1Affine{aggPi.qTau, aggPi.rTau}, []bls.G2Affine{w.crs.vHTau, w.crs.g2a})

	res = res && lhs.Equal(&rhs)

	// 2.2 Checking r(tau) = q_r(tau)tau + aggPk/n  is correct
	var aggPkN bls.G1Affine
	nInv := fr.NewElement(uint64(w.n))
	nInv.Inverse(&nInv)
	aggPkN.ScalarMultiplication(&sigma.aggPk, nInv.BigInt(&big.Int{}))

	lhs, _ = bls.Pair([]bls.G1Affine{aggPi.rTau}, []bls.G2Affine{w.crs.g2a})
	rhs, _ = bls.Pair([]bls.G1Affine{aggPi.qrTau, aggPkN}, []bls.G2Affine{w.crs.g2Tau, w.crs.g2a})

	res = res && lhs.Equal(&rhs)

	return res
}
