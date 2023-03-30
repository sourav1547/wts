package multsig

import (
	"fmt"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/assert"
)

func TestBLS(t *testing.T) {
	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte{})

	n := 1 << 5
	ths := n / 2
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenBLSCRS(n)
	m := NewBLS(n, ths, crs)

	var signers []int
	var sigmas []bls.G2Jac
	for i := 0; i < ths+1; i++ {
		signers = append(signers, i)
		sigmas = append(sigmas, m.psign(msg, m.pp.signers[i]))
	}

	msig := m.verifyCombine(roMsg, signers, sigmas)
	fmt.Println("Num signers", len(signers), "claimed weight", ths)
	assert.Equal(t, m.gverify(roMsg, msig), true, "BLS Threshold Signature")
}
