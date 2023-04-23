package wts

import (
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
	pk.ScalarMultiplication(&g1, sk.BigInt(big.NewInt(0)))

	signer := MTSParty{
		seckey:     *sk.BigInt(big.NewInt(0)),
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
	ro_msg, _ := bls.HashToG2(msg, dst)
	assert.Equal(t, m.mts_pverify(ro_msg, sigma, pk_aff), true)
}

func TestLag(t *testing.T) {
	n := 4
	idxs := make([]fr.Element, 4)
	m := NewMTS(n)

	for i := 0; i < n; i++ {
		idxs[i].SetInt64(int64(i + 1))
	}

	res := GetLagAt(0, idxs)
	var sk fr.Element
	for i := 0; i < n; i++ {
		var temp_sk, prod fr.Element
		prod.Mul(&res[i], temp_sk.SetBigInt(&m.crs.secret_keys[i]))
		sk.Add(&sk, &prod)
	}
	var ppk bls.G1Jac
	ppk.ScalarMultiplication(&m.g1, sk.BigInt(big.NewInt(0)))
	assert.Equal(t, ppk, m.crs.vk)
}

func TestMTSCombine(t *testing.T) {
	n := 4
	ths := n - 2
	m := NewMTS(n)
	parties := make([]MTSParty, n)
	var pk_aff bls.G1Affine
	signs := make([]Sig, n)

	msg := []byte("hello world")
	var dst []byte
	ro_msg, _ := bls.HashToG2(msg, dst)
	var ro_msg_jac bls.G2Jac
	ro_msg_jac.FromAffine(&ro_msg)

	for i := 0; i < n; i++ {
		parties[i] = MTSParty{
			seckey:     m.crs.secret_keys[i],
			pubkey:     m.crs.public_keys[i],
			pubkey_aff: *pk_aff.FromJacobian(&m.crs.public_keys[i]),
		}
		signs[i] = Sig{
			index: i + 1,
			sigma: m.mts_psign(msg, parties[i]),
		}
	}
	sigma := m.mts_combine(signs[:ths])
	assert.Equal(t, m.mts_gverify(ro_msg, sigma, ths), true)
}
