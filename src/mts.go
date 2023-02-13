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
	coms        []bls.G1Affine // g^{p(-1)},...,g^{p(-n)}
	coms_k      []bls.G1Affine // g^{p(-1)k},...,g^{p(-n)k}
	secret_keys []fr.Element   // signing keys of signers
	public_keys []bls.G1Jac    // verification keys of signers
	gk          bls.G2Jac      // g2^k
	vk          bls.G1Jac      // g^{p(0)}
	vk_aff      bls.G1Affine
	sk          fr.Element
}

type MTSParty struct {
	crs        []bls.G1Jac // not sure what is this for
	seckey     *big.Int
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

func (m *MTS) mts_key_gen() {
	m.g1_inv.Neg(&m.g1)
	m.g1_inv_aff.FromJacobian(&m.g1_inv)

	// build polynomial
	spoly := make(poly.Polynomial, m.n)
	for i := 0; i < m.n; i++ {
		spoly[i].SetRandom()
	}

	skeys := make([]fr.Element, m.n)
	vkeys := make([]bls.G1Jac, m.n)
	for i := 0; i < m.n; i++ {
		idx := fr.NewElement(uint64(i + 1))
		skeys[i] = spoly.Eval(&idx)
		vkeys[i].ScalarMultiplication(&m.g1, skeys[i].ToBigInt(big.NewInt(0)))
	}

	var (
		alpha     fr.Element
		gk        bls.G2Jac
		alpha_int big.Int
		vk        bls.G1Jac
		vk_aff    bls.G1Affine
		zero      fr.Element
	)
	com_keys := make([]fr.Element, m.n)
	coms := make([]bls.G1Affine, m.n)
	coms_k := make([]bls.G1Affine, m.n)
	zero.SetZero()

	sk := spoly.Eval(&zero)
	vk.ScalarMultiplication(&m.g1, sk.ToBigInt(big.NewInt(0)))
	vk_aff.FromJacobian(&vk)

	alpha.SetRandom()
	alpha.ToBigInt(&alpha_int)
	gk.ScalarMultiplication(&m.g2, &alpha_int)

	var (
		coms_i   bls.G1Jac
		coms_k_i bls.G1Jac
	)

	for i := 1; i <= m.n; i++ {
		idx := fr.NewElement(uint64(i))
		idx.Sub(&zero, &idx)
		com_keys[i-1] = spoly.Eval(&idx)
		coms_i.ScalarMultiplication(&m.g1, com_keys[i-1].ToBigInt(big.NewInt(0)))
		coms_k_i.ScalarMultiplication(&coms_i, &alpha_int)
		coms[i-1].FromJacobian(&coms_i)
		coms_k[i-1].FromJacobian(&coms_k_i)
	}

	m.crs = MTSPublicParams{
		coms:        coms,
		coms_k:      coms_k,
		secret_keys: skeys,
		public_keys: vkeys,
		gk:          gk,
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

	sigma.ScalarMultiplication(&ro_msg_jac, signer.seckey)
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
	gpubk.MultiExp(m.crs.coms_k[:(m.n-t)], lags[t:], ecc.MultiExpConfig{ScalarsMont: true})

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
	g_alpha_aff.FromJacobian(&(m.crs.gk))

	d, _ := bls.Pair([]bls.G1Affine{gpubk_aff}, []bls.G2Affine{m.g2_aff})
	e, _ := bls.Pair([]bls.G1Affine{gpub_aff}, []bls.G2Affine{g_alpha_aff})
	return d.Equal(&e)
}
