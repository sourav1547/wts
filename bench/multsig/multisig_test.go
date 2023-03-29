package multsig

import (
	"fmt"
	"math/rand"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/assert"
)

func TestMultSig(t *testing.T) {
	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte{})

	n := 1 << 4
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	m := NewMultSig(n, weights)

	var signers []int
	var sigmas []bls.G2Jac
	for i := 0; i < n; i++ {
		if rand.Intn(2) == 1 {
			signers = append(signers, i)
			sigmas = append(sigmas, m.psign(msg, m.crs.parties[i]))
		}
	}

	msig := m.verifyCombine(roMsg, signers, sigmas)
	fmt.Println("Num signers", len(signers), "claimed weight", msig.t)
	assert.Equal(t, m.gverify(roMsg, msig), true)
}
