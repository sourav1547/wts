package multsig

import (
	"fmt"
	"math/big"

	wts "wts/src"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type MultSigParams struct {
	sKeys   []fr.Element // signing keys of signers
	pKeys   []bls.G1Jac  // verification keys of signers
	parties []MultSigParty
}

type MultSigParty struct {
	sKey  fr.Element
	pKey  bls.G1Affine
	index int
}

type MultSignature struct {
	sig     bls.G2Affine
	signers []int
	t       int
}

type MultSig struct {
	crs     MultSigParams
	n       int
	weights []int
	g1      bls.G1Jac
	g1a     bls.G1Affine
	g1Inv   bls.G1Jac
	g1InvAf bls.G1Affine
	g2      bls.G2Jac
	g2a     bls.G2Affine
}

func NewMultSig(n int, weights []int) MultSig {
	g1, g2, g1a, g2a := bls.Generators()
	m := MultSig{
		n:       n,
		weights: weights,
		g1:      g1,
		g1a:     g1a,
		g2:      g2,
		g2a:     g2a,
	}
	m.g1Inv.Neg(&m.g1)
	m.g1InvAf.FromJacobian(&m.g1Inv)
	m.keyGen()

	return m
}

func (m *MultSig) keyGen() {
	var vk bls.G1Jac
	var vkAf bls.G1Affine
	skeys := make([]fr.Element, m.n)
	vkeys := make([]bls.G1Jac, m.n)
	parties := make([]MultSigParty, m.n)

	// Sampling random keys for each signer and computing the corresponding public key
	for i := 0; i < m.n; i++ {
		skeys[i].SetRandom()
		vk.ScalarMultiplication(&m.g1, skeys[i].BigInt(&big.Int{}))

		vkeys[i] = vk
		parties[i] = MultSigParty{
			sKey:  skeys[i],
			pKey:  *vkAf.FromJacobian(&vk),
			index: i,
		}
	}

	m.crs = MultSigParams{
		sKeys:   skeys,
		pKeys:   vkeys,
		parties: parties,
	}
}

// Takes the signing key and signs the message
func (m *MultSig) psign(msg wts.Message, signer MultSigParty) bls.G2Jac {
	var (
		dst   []byte
		sigma bls.G2Jac
		roMsg bls.G2Jac
	)
	roMsgAf, err := bls.HashToG2(msg, dst)
	roMsg.FromAffine(&roMsgAf)

	if err != nil {
		fmt.Printf("Signature error!")
	}

	sigma.ScalarMultiplication(&roMsg, signer.sKey.BigInt(&big.Int{}))
	return sigma
}

// Takes the msg, signature and signing key and verifies the signature
func (m *MultSig) pverify(roMsg bls.G2Affine, sigma bls.G2Jac, vk bls.G1Affine) bool {
	var sigmaAff bls.G2Affine
	sigmaAff.FromJacobian(&sigma)

	P := []bls.G1Affine{vk, m.g1InvAf}
	Q := []bls.G2Affine{roMsg, sigmaAff}

	res, err := bls.PairingCheck(P, Q)
	if err != nil {
		fmt.Println("Panic mts verification failed")
	}
	return res
}

func (m *MultSig) verifyCombine(msg bls.G2Affine, signers []int, sigmas []bls.G2Jac) MultSignature {

	var vfSigners []int
	var lIdx []int
	for i, idx := range signers {
		if m.pverify(msg, sigmas[i], m.crs.parties[idx].pKey) {
			vfSigners = append(vfSigners, signers[i])
			lIdx = append(lIdx, i)
		}
	}

	vfSigs := make([]bls.G2Jac, len(vfSigners))
	for i, idx := range lIdx {
		vfSigs[i] = sigmas[idx]
	}

	return m.combine(vfSigners, vfSigs)
}

// The multisignature aggregation function
// This function assumes that the signatures are already validated
// Here we are assuming that rouge key attack has been handled using Proof-of-Possesion
func (m *MultSig) combine(signers []int, sigmas []bls.G2Jac) MultSignature {
	wt := 0
	var aggSig bls.G2Jac
	for i, idx := range signers {
		aggSig.AddAssign(&sigmas[i])
		wt += m.weights[idx]
	}
	var aggSigAf bls.G2Affine
	aggSigAf.FromJacobian(&aggSig)

	return MultSignature{
		sig:     aggSigAf,
		signers: signers,
		t:       wt,
	}
}

func (m *MultSig) gverify(msg bls.G2Affine, msig MultSignature) bool {
	var (
		apk   bls.G1Jac    // Aggregated public key
		apkAf bls.G1Affine // Affine apk
	)

	wt := 0
	for _, idx := range msig.signers {
		apk.AddAssign(&m.crs.pKeys[idx])
		wt += m.weights[idx]
	}
	apkAf.FromJacobian(&apk)

	res, _ := bls.PairingCheck([]bls.G1Affine{apkAf, m.g1InvAf}, []bls.G2Affine{msg, msig.sig})
	return res && (wt >= msig.t)
}
