package wts

import (
	"math"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poly "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

type IPA struct {
	n     int
	ell   int
	afgho AFGHO
	ped   Ped
	kzg   KZG
}

type IPAProof struct {
	comm_g bls.GT
	comm_f bls.G1Jac
	kzg_pf KZGIPA
	proof  []Proof
}

type Proof struct {
	left  bls.G1Jac
	right bls.G2Jac
	x     fr.Element
}

func NewIPA(n int, kzg_crs []bls.G1Affine) IPA {
	ell := int(math.Log2(float64(n)))
	return IPA{
		n:     n,
		ell:   ell,
		afgho: NewAFGHO(n),
		ped:   NewPed(n),
		kzg:   NewKZG(n, kzg_crs),
	}
}

// TODO: To optimize this
func (p *IPA) prove(gs []bls.G1Affine, fs []fr.Element) IPAProof {
	proofs := make([]Proof, p.ell)

	comm_g := p.afgho.commit_g1(gs)
	comm_f := p.ped.commit(fs)
	xs := make([]fr.Element, p.ell)

	for i := 0; i < p.ell; i++ {
		// FIXME
		proofs[i] = Proof{}
		xs[i].SetRandom()
	}

	kzg_poly := poly.Polynomial(xs)
	kzg_pf := p.kzg.comm_prove_rand(kzg_poly)

	return IPAProof{
		comm_g: comm_g,
		comm_f: comm_f,
		kzg_pf: kzg_pf,
		proof:  proofs,
	}
}

// FIXME: Incomplete implementation
func (p *IPA) verify_proof(pf IPAProof, comm_g bls.GT, comm_f bls.G1Jac) bool {
	if comm_g.Equal(&pf.comm_g) && comm_f.Equal(&pf.comm_f) {
		x_poly := make(poly.Polynomial, p.ell)

		for i := 0; i < p.ell; i++ {
			// FIXME: Not implemented
			x_poly[i].SetRandom()
		}

		var x fr.Element
		x.SetRandom()
		y := x_poly.Eval(&x)
		return p.kzg.verify(pf.kzg_pf.p_tau, pf.kzg_pf.q_tau, x, y)
	}
	return false
}
