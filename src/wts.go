package wts

import (
	"fmt"
	"math"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type WTSParty struct {
	weight int
	ell    int
	hw     int              // Hamming weight of the signer
	mtsp   map[int]MTSParty // TODO: Nnot sure why we need a map her.
	idxs   []int            // Stores the index in each MTS
}

type WTSSig struct {
	sigma  []MTSSig
	weight int
}

type WTS struct {
	mts     []MTS // List of MTS instances
	wmax    int   // Maximum allowable weight per signer
	ell     int   // Number of denomination
	weights []int // Weight distribution
	n       int   // Total number of signers
	ths     int   // Signing threshold
}

func NewWTS(n, ths, ell int, weights []int) (WTS, []WTSParty) {
	w := WTS{
		wmax:    int(math.Pow(2, float64(ell))),
		n:       n,
		ths:     ths,
		ell:     ell,
		weights: weights,
	}
	parties := w.wts_key_gen()
	return w, parties
}

func (w *WTS) wts_key_gen() []WTSParty {
	parties := make([]WTSParty, w.n)
	w.mts = make([]MTS, w.ell)

	// calculating signers in each denominations
	nks := make([]int, w.ell)
	for i := 0; i < w.n; i++ {
		all_pos := bin_pos(w.weights[i])
		for _, pos := range all_pos {
			nks[pos] = nks[pos] + 1
		}
	}

	// FIXME: Have to figure out what to do when certain nks are zero.
	for i := 0; i < w.ell; i++ {
		if nks[i] > 0 {
			w.mts[i] = NewMTS(nks[i])
		}
	}

	var pk_aff bls.G1Affine
	cur_counts := make([]int, w.ell)
	for i := 0; i < w.n; i++ {
		weight := w.weights[i]
		hw := ham_weight(weight)
		all_pos := bin_pos(weight)

		// For each signer, creating one MTS signer for every denomination
		mtsp := make(map[int]MTSParty, hw)
		idxs := make([]int, hw)
		for ii, pos := range all_pos {
			idx := cur_counts[pos]
			mtsp[pos] = MTSParty{
				seckey:     w.mts[pos].crs.secret_keys[idx],
				pubkey:     w.mts[pos].crs.public_keys[idx],
				pubkey_aff: *pk_aff.FromJacobian(&w.mts[pos].crs.public_keys[idx]),
			}
			idxs[ii] = idx
			cur_counts[pos] += 1
		}

		parties[i] = WTSParty{
			weight: weight,
			ell:    w.ell,
			hw:     hw,
			mtsp:   mtsp,
			idxs:   idxs,
		}
	}

	return parties
}

// Takes the singing party and signs the message
// Returns a list of signatures, one for each MTS party
func (w *WTS) wts_psign(msg Message, signer WTSParty) []bls.G2Jac {
	var (
		dst        []byte
		ro_msg_jac bls.G2Jac
	)
	ro_msg, err := bls.HashToCurveG2SSWU(msg, dst)
	ro_msg_jac.FromAffine(&ro_msg)

	if err != nil {
		fmt.Printf("Signature error!")
		return []bls.G2Jac{}
	}

	sigmas := make([]bls.G2Jac, signer.hw)
	for i := 0; i < signer.hw; i++ {
		idx := signer.idxs[i]
		sk := signer.mtsp[idx].seckey
		sigmas[i].ScalarMultiplication(&ro_msg_jac, &sk)
	}

	return sigmas
}

// Takes the signing key and signs the message
func (w *WTS) wts_pverify(msg bls.G2Affine, sigmas []bls.G2Jac, signer WTSParty) bool {
	var sigma_aff bls.G2Affine
	g1_inv_aff := w.mts[0].g1_inv_aff

	for i := 0; i < signer.hw; i++ {
		sigma_aff.FromJacobian(&sigmas[i])
		idx := signer.idxs[i]

		P := []bls.G1Affine{signer.mtsp[idx].pubkey_aff, g1_inv_aff}
		Q := []bls.G2Affine{msg, sigma_aff}

		res, err := bls.PairingCheck(P, Q)
		if err != nil {
			fmt.Println("Panic mts verification failed")
		}
		if !res {
			return false
		}
	}
	return true
}

// The combine function
func (w *WTS) wts_combine(sigmas []MTSSig) WTSSig {
	return WTSSig{}
}

// WTS global verify
// TODO: I think it might be better to make a class here
func (w *WTS) wts_gverify(msg Message, sigma WTSSig, weight int) bool {
	return true
}

// Only missing piece is the
