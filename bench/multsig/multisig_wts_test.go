package multsig

import (
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/assert"
)

func TestMultSigWTS(t *testing.T) {
	var dst []byte
	msg := []byte("hello world")
	ro_msg, _ := bls.HashToCurveG2SSWU(msg, dst)

	n := 1 << 12
	ths := 1 << 4
	w := NewMulWTS(n, ths)
	sigmas := w.sign(msg)
	msig, _ := w.combine(ro_msg, sigmas)
	assert.Equal(t, w.verify(ro_msg, msig), true)
}
