package wts

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poly "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

type MTSPublicParams struct {
	coms        []bls.G1Affine   // g^{p(-1)},...,g^{p(-n)}
	coms_ks     [][]bls.G1Affine // g^{p(-1)k},...,g^{p(-n)k}
	secret_keys []big.Int        // signing keys of signers
	public_keys []bls.G1Jac      // verification keys of signers
	gks         []bls.G2Jac      // g2^k
	vk          bls.G1Jac        // g^{p(0)}
	vk_aff      bls.G1Affine
	sk          fr.Element
}

type MTSParty struct {
	seckey     big.Int
	pubkey     bls.G1Jac
	pubkey_aff bls.G1Affine
}

type MTSSig struct {
	gpub  bls.G1Jac
	mpriv bls.G2Jac
	gpubk bls.G1Jac
	ths   int
}

type Sig struct {
	sigma bls.G2Jac
	index int
}

type MTS struct {
	crs        MTSPublicParams
	n          int
	g1         bls.G1Jac
	g1_inv     bls.G1Jac
	g2         bls.G2Jac
	g1_aff     bls.G1Affine
	g1_inv_aff bls.G1Affine
	g2_aff     bls.G2Affine
}

func NewMTS(n int) MTS {
	g1, g2, g1_aff, g2_aff := bls.Generators()

	m := MTS{
		n:      n,
		g1:     g1,
		g1_aff: g1_aff,
		g2:     g2,
		g2_aff: g2_aff,
	}
	m.g1_inv.Neg(&m.g1)
	m.g1_inv_aff.FromJacobian(&m.g1_inv)
	m.mts_key_gen()

	return m
}

func (m *MTS) mts_key_gen() {
	// build polynomial
	spoly := make(poly.Polynomial, m.n)
	for i := 0; i < m.n; i++ {
		spoly[i].SetRandom()
	}

	skeys := make([]big.Int, m.n)
	vkeys := make([]bls.G1Jac, m.n)
	for i := 0; i < m.n; i++ {
		idx := fr.NewElement(uint64(i + 1))
		temp := spoly.Eval(&idx)
		temp.ToBigInt(&skeys[i])
		vkeys[i].ScalarMultiplication(&m.g1, &skeys[i])
	}

	var (
		vk     bls.G1Jac
		vk_aff bls.G1Affine
		zero   fr.Element
	)

	gks := make([]bls.G2Jac, m.n)
	coms := make([]bls.G1Affine, m.n)
	coms_jac := make([]bls.G1Jac, m.n)
	coms_ks := make([][]bls.G1Affine, m.n)

	zero.SetZero()
	sk := spoly.Eval(&zero)
	vk.ScalarMultiplication(&m.g1, sk.ToBigInt(big.NewInt(0)))
	vk_aff.FromJacobian(&vk)

	var (
		idx     fr.Element
		com_key fr.Element
	)
	for i := 1; i <= m.n; i++ {
		idx = fr.NewElement(uint64(i))
		idx.Sub(&zero, &idx)
		com_key = spoly.Eval(&idx)
		coms_jac[i-1].ScalarMultiplication(&m.g1, com_key.ToBigInt(big.NewInt(0)))
		coms[i-1].FromJacobian(&coms_jac[i-1])
	}

	var (
		alpha     fr.Element
		alpha_int big.Int
		coms_k_i  bls.G1Jac
	)
	for i := 0; i < m.n; i++ {
		alpha.SetRandom()
		alpha.ToBigInt(&alpha_int)
		gks[i].ScalarMultiplication(&m.g2, &alpha_int)

		coms_ks[i] = make([]bls.G1Affine, m.n-i)

		for ii := 0; ii < m.n-i; ii++ {
			coms_k_i.ScalarMultiplication(&coms_jac[ii], &alpha_int)
			coms_ks[i][ii].FromJacobian(&coms_k_i)
		}
	}

	m.crs = MTSPublicParams{
		coms:        coms,
		coms_ks:     coms_ks,
		secret_keys: skeys,
		public_keys: vkeys,
		gks:         gks,
		vk:          vk,
		vk_aff:      vk_aff,
		sk:          sk,
	}
}

// Takes the signing key and signs the message
func (m *MTS) mts_psign(msg Message, signer MTSParty) bls.G2Jac {
	var (
		dst        []byte
		sigma      bls.G2Jac
		ro_msg_jac bls.G2Jac
	)
	ro_msg, err := bls.HashToCurveG2SSWU(msg, dst)
	ro_msg_jac.FromAffine(&ro_msg)

	if err != nil {
		fmt.Printf("Signature error!")
		return bls.G2Jac{}
	}

	sigma.ScalarMultiplication(&ro_msg_jac, &signer.seckey)
	return sigma
}

// Takes the signing key and signs the message
func (m *MTS) mts_pverify(ro_msg bls.G2Affine, sigma bls.G2Jac, vk bls.G1Affine) bool {
	var sigma_aff bls.G2Affine
	sigma_aff.FromJacobian(&sigma)

	P := []bls.G1Affine{vk, m.g1_inv_aff}
	Q := []bls.G2Affine{ro_msg, sigma_aff}

	res, err := bls.PairingCheck(P, Q)
	if err != nil {
		fmt.Println("Panic mts verification failed")
	}
	return res
}

// The combine function
func (m *MTS) mts_combine(sigmas []Sig) MTSSig {
	t := len(sigmas)
	idxs := make([]fr.Element, m.n)
	sigs := make([]bls.G2Affine, t)
	var (
		gpub  bls.G1Jac
		mpriv bls.G2Jac
		gpubk bls.G1Jac
	)

	zero := fr.NewElement(uint64(0))
	for i := 0; i < t; i++ {
		idxs[i] = fr.NewElement(uint64(sigmas[i].index))
		sigs[i].FromJacobian(&sigmas[i].sigma)
	}

	for i := 1; i <= m.n-t; i++ {
		idx := fr.NewElement(uint64(i))
		idxs[t+i-1].Sub(&zero, &idx)
	}

	lags := get_lag_at(0, idxs)

	mpriv.MultiExp(sigs, lags[:t], ecc.MultiExpConfig{ScalarsMont: true})
	gpub.MultiExp(m.crs.coms[:(m.n-t)], lags[t:], ecc.MultiExpConfig{ScalarsMont: true})
	gpubk.MultiExp(m.crs.coms_ks[t][:(m.n-t)], lags[t:], ecc.MultiExpConfig{ScalarsMont: true})

	return MTSSig{
		gpub:  gpub,
		mpriv: mpriv,
		gpubk: gpubk,
	}
}

// MTS global verify
// TODO: I think it might be better to make a class here
// TODO: To optimize this
func (m *MTS) mts_gverify(msg_aff bls.G2Affine, sig MTSSig, t int) bool {
	var (
		gpub_aff  bls.G1Affine // g_1^pub
		mpriv_aff bls.G2Affine // H(m)^priv
		gpubk_aff bls.G1Affine // g_1^pub'
	)

	gpub_aff.FromJacobian(&sig.gpub)
	mpriv_aff.FromJacobian(&sig.mpriv)
	gpubk_aff.FromJacobian(&sig.gpubk)

	a, _ := bls.Pair([]bls.G1Affine{m.crs.vk_aff}, []bls.G2Affine{msg_aff})
	b, _ := bls.Pair([]bls.G1Affine{gpub_aff}, []bls.G2Affine{msg_aff})
	c, _ := bls.Pair([]bls.G1Affine{m.g1_aff}, []bls.G2Affine{mpriv_aff})

	b.Mul(&b, &c)
	if !a.Equal(&b) {
		return false
	}

	var g_alpha_aff bls.G2Affine
	g_alpha_aff.FromJacobian(&(m.crs.gks[t]))

	d, _ := bls.Pair([]bls.G1Affine{gpubk_aff}, []bls.G2Affine{m.g2_aff})
	e, _ := bls.Pair([]bls.G1Affine{gpub_aff}, []bls.G2Affine{g_alpha_aff})
	return d.Equal(&e)
}
