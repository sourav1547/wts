package multsig

import (
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	wts "github.com/sourav1547/wts/src"
)

type MulWTS struct {
	mults MultSig
	n     int
}

// FIXME: To take in some weight distribution and create the signers accordingly
func NewMulWTS(n, ths int) MulWTS {
	return MulWTS{
		n:     n,
		mults: NewMultSig(n),
	}
}

// Sign given a specific required threshold

func (w *MulWTS) sign(msg wts.Message) []Sig {
	// Signing phase
	sigmas := make([]Sig, w.n)
	for i := 0; i < w.n; i++ {
		sigmas[i] = w.mults.psign(msg, w.mults.crs.parties[i])
	}
	return sigmas

	/**
	* TODO: To finalize how should we order the signers
	**/

}

// We assume that aggregation function also validates the signature
func (w *MulWTS) combine(ro_msg bls.G2Affine, sigmas []Sig) (MultSignature, error) {

	// Verifying the signatures
	var vf_sigs []Sig
	for _, sigma := range sigmas {
		if w.mults.pverify(ro_msg, sigma) {
			vf_sigs = append(vf_sigs, sigma)
		}
	}

	// Aggregating the values and returning
	return w.mults.combine(vf_sigs)
}

func (w *MulWTS) verify(ro_msg bls.G2Affine, msig MultSignature) bool {
	return w.mults.gverify(ro_msg, msig)
}
