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

func BenchmarkMulSigUW(b *testing.B) {
	testCases := []struct {
		name string
		n, t int
	}{
		{"256", 256, 256},
		{"1024", 1024, 1024},
		{"4096", 4096, 4096},
	}

	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte{})

	for _, tc := range testCases {

		weights := make([]int, tc.n)
		for i := 0; i < tc.n; i++ {
			weights[i] = 1
		}
		m := NewMultSig(tc.n, weights)

		// Picking the first t nodes as things are unweighted
		signers := make([]int, tc.t)
		sigmas := make([]bls.G2Jac, tc.t)
		for i := 0; i < tc.t; i++ {
			signers[i] = i
			sigmas[i] = m.psign(msg, m.crs.parties[i])
		}

		var msig MultSignature
		b.Run(tc.name+"-agg", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				msig = m.combine(signers, sigmas)
			}
		})

		b.Run(tc.name+"-ver", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.gverify(roMsg, msig)
			}
		})
	}
}
