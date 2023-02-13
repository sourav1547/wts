package wts

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestMTSPSign(t *testing.T) {
	msg := []byte("hello world")
	g1, _, _, _ := bls.Generators()
	var (
		sk                 fr.Element
		pk, g1_inv         bls.G1Jac
		pk_aff, g1_inv_aff bls.G1Affine
	)

	sk.SetRandom()
	pk.ScalarMultiplication(&g1, sk.ToBigInt(big.NewInt(0)))

	signer := MTSParty{
		crs:        make([]bls.G1Jac, 1),
		seckey:     sk.ToBigInt(big.NewInt(0)),
		pubkey:     pk,
		pubkey_aff: *pk_aff.FromJacobian(&pk),
	}

	g1_inv.ScalarMultiplication(&g1, big.NewInt(-1))
	g1_inv_aff.FromJacobian(&g1_inv)
	m := MTS{
		g1:         g1,
		g1_inv:     g1_inv,
		g1_inv_aff: g1_inv_aff,
	}
	sigma := m.mts_psign(msg, signer)
	var dst []byte
	ro_msg, _ := bls.HashToCurveG2SSWU(msg, dst)
	assert.Equal(t, m.mts_pverify(ro_msg, sigma, pk_aff), true)
}

func TestLag(t *testing.T) {
	n := 4
	idxs := make([]fr.Element, 4)
	g1, g2, _, _ := bls.Generators()

	m := MTS{
		n:  n,
		g1: g1,
		g2: g2,
	}
	m.mts_key_gen()

	for i := 0; i < n; i++ {
		idxs[i].SetInt64(int64(i + 1))
	}

	res := get_lag_at(0, idxs)
	var sk fr.Element
	for i := 0; i < n; i++ {
		var prod fr.Element
		prod.Mul(&res[i], &m.crs.secret_keys[i])
		sk.Add(&sk, &prod)
	}
	fmt.Println(sk.Equal(&m.crs.sk))
	var ppk bls.G1Jac
	ppk.ScalarMultiplication(&m.g1, sk.ToBigInt(big.NewInt(0)))
	assert.Equal(t, ppk, m.crs.vk)
}

func TestMTSCombine(t *testing.T) {
	g1, g2, g1_aff, g2_aff := bls.Generators()
	n := 1

	m := MTS{
		n:      n,
		g1:     g1,
		g1_aff: g1_aff,
		g2:     g2,
		g2_aff: g2_aff,
	}
	m.mts_key_gen()
	parties := make([]MTSParty, n)
	var pk_aff bls.G1Affine
	signs := make([]Sig, n)

	msg := []byte("hello world")
	var dst []byte
	ro_msg, _ := bls.HashToCurveG2SSWU(msg, dst)
	var ro_msg_jac bls.G2Jac
	ro_msg_jac.FromAffine(&ro_msg)

	for i := 0; i < n; i++ {
		parties[i] = MTSParty{
			seckey:     m.crs.secret_keys[i].ToBigInt(big.NewInt(0)),
			pubkey:     m.crs.public_keys[i],
			pubkey_aff: *pk_aff.FromJacobian(&m.crs.public_keys[i]),
		}
		signs[i] = Sig{
			index: i + 1,
			sigma: m.mts_psign(msg, parties[i]),
		}
	}
	sigma := m.mts_combine(signs)

	var s bls.G2Jac
	var ppk bls.G1Jac
	s.ScalarMultiplication(&ro_msg_jac, m.crs.sk.ToBigInt(big.NewInt(0)))
	ppk.ScalarMultiplication(&m.g1, m.crs.sk.ToBigInt(big.NewInt(0)))
	// assert.Equal(t, s, sigma.mpriv)
	if s.Equal(&sigma.mpriv) {
		fmt.Println("sig match")
	}

	if ppk.Equal(&sigma.gpubk) {
		fmt.Println("sig match")
	}
	assert.Equal(t, m.mts_gverify(ro_msg, sigma, n-1), true)
}
