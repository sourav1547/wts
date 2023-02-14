package wts

import (
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/assert"
)

func TestWTSPSign(t *testing.T) {
	msg := []byte("hello world")
	n := 4
	ths := n - 1
	ell := 8
	weights := []int{15, 2, 4, 8}

	w, parties := NewWTS(n, ths, ell, weights)
	sigmas := w.wts_psign(msg, parties[0])

	var dst []byte
	ro_msg, _ := bls.HashToCurveG2SSWU(msg, dst)

	assert.Equal(t, w.wts_pverify(ro_msg, sigmas, parties[0]), true)
}
