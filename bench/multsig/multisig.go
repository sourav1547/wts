package multsig

import (
	"fmt"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	wts "github.com/sourav1547/wts/src"

	ba "github.com/Workiva/go-datastructures/bitarray"
)

type MultSigParams struct {
	secret_keys []big.Int   // signing keys of signers
	public_keys []bls.G1Jac // verification keys of signers
	weights     []int       // weight of each signer
	parties     []MultSigParty
}

type MultSigParty struct {
	seckey     big.Int
	pubkey     bls.G1Jac
	pubkey_aff bls.G1Affine
	index      int
}

type MultSignature struct {
	sig     bls.G2Jac
	signers ba.BitArray
	t       int
}

type Sig struct {
	sigma bls.G2Jac
	index int
}

type MultSig struct {
	crs        MultSigParams
	n          int
	g1         bls.G1Jac
	g1_aff     bls.G1Affine
	g1_inv     bls.G1Jac
	g1_inv_aff bls.G1Affine
	g2         bls.G2Jac
	g2_aff     bls.G2Affine
}

func NewMultSig(n int) MultSig {
	g1, g2, g1_aff, g2_aff := bls.Generators()

	m := MultSig{
		n:      n,
		g1:     g1,
		g1_aff: g1_aff,
		g2:     g2,
		g2_aff: g2_aff,
	}
	m.g1_inv.Neg(&m.g1)
	m.g1_inv_aff.FromJacobian(&m.g1_inv)
	m.key_gen()

	return m
}

func (m *MultSig) key_gen() {
	var (
		sk     fr.Element
		vk     bls.G1Jac
		vk_aff bls.G1Affine
	)

	skeys := make([]big.Int, m.n)
	vkeys := make([]bls.G1Jac, m.n)
	parties := make([]MultSigParty, m.n)
	weights := make([]int, m.n)

	// Sampling random keys for each signer and computing the corresponding public key
	for i := 0; i < m.n; i++ {
		sk.SetRandom()
		sk.ToBigInt(&skeys[i])
		vk.ScalarMultiplication(&m.g1, &skeys[i])
		vk_aff.FromJacobian(&vk)

		vkeys[i] = vk
		parties[i] = MultSigParty{
			seckey:     skeys[i],
			pubkey:     vk,
			pubkey_aff: vk_aff,
			index:      i,
		}
		weights[i] = 1
	}

	m.crs = MultSigParams{
		secret_keys: skeys,
		public_keys: vkeys,
		parties:     parties,
		weights:     weights,
	}
}

// Takes the signing key and signs the message
func (m *MultSig) psign(msg wts.Message, signer MultSigParty) Sig {
	var (
		dst        []byte
		sigma      bls.G2Jac
		ro_msg_jac bls.G2Jac
	)
	ro_msg, err := bls.HashToCurveG2SSWU(msg, dst)
	ro_msg_jac.FromAffine(&ro_msg)

	if err != nil {
		fmt.Printf("Signature error!")
		return Sig{}
	}

	sigma.ScalarMultiplication(&ro_msg_jac, &signer.seckey)
	return Sig{
		sigma: sigma,
		index: signer.index,
	}
}

// Takes the signing key and signs the message
func (m *MultSig) pverify(ro_msg bls.G2Affine, signature Sig) bool {
	var sigma_aff bls.G2Affine
	sigma := signature.sigma
	sigma_aff.FromJacobian(&sigma)

	vk := m.crs.parties[signature.index].pubkey_aff

	P := []bls.G1Affine{vk, m.g1_inv_aff}
	Q := []bls.G2Affine{ro_msg, sigma_aff}

	res, err := bls.PairingCheck(P, Q)
	if err != nil {
		fmt.Println("Panic mts verification failed")
	}
	return res
}

// The multisignature aggregation function
// This function assumes that the signatures are already validated
// Here we are assuming that rouge key attack has been handled using Proof-of-Possesion
func (m *MultSig) combine(sigmas []Sig) (MultSignature, error) {
	var sig bls.G2Jac
	signers := ba.NewBitArray(uint64(m.n))
	wt := 0

	// FIXME: Create the list of signers properly
	for i := 0; i < len(sigmas); i++ {
		sig.AddAssign(&sigmas[i].sigma)
		signers.SetBit(uint64(sigmas[i].index))
		wt += m.crs.weights[i]

	}

	return MultSignature{
		sig:     sig,
		signers: signers,
		t:       wt,
	}, nil
}

// TODO: To optimize this
func (m *MultSig) gverify(msg_aff bls.G2Affine, msig MultSignature) bool {
	var (
		apk     bls.G1Jac    // Aggregated public key
		apk_aff bls.G1Affine // Affine apk
		sig_aff bls.G2Affine // H(m)^priv
	)

	for i := 0; i < m.n; i++ {
		set, _ := msig.signers.GetBit(uint64(i))
		if set {
			apk.AddAssign(&m.crs.public_keys[i])
		}
	}
	apk_aff.FromJacobian(&apk)
	sig_aff.FromJacobian(&msig.sig)

	lhs, _ := bls.Pair([]bls.G1Affine{apk_aff}, []bls.G2Affine{msg_aff})
	rhs, _ := bls.Pair([]bls.G1Affine{m.g1_aff}, []bls.G2Affine{sig_aff})

	return lhs.Equal(&rhs)
}
