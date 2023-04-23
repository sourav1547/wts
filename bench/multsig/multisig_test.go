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

func BenchmarkMulSigCombineUW(b *testing.B) {
	testCases := []struct {
		name string
		n, t int
	}{
		{"256-129", 256, 129},
		{"1024-513", 1024, 513},
		{"4096-2049", 4096, 2049},
		{"256-171", 256, 171},
		{"1024-683", 1024, 683},
		{"4096-2731", 4096, 2731},
	}

	msg := []byte("hello world")

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {

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

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.combine(signers, sigmas)
			}
		})
	}
}

func BenchmarkMulSigVerifyUW(b *testing.B) {
	testCases := []struct {
		name string
		n, t int
	}{
		{"256-129", 256, 129},
		{"1024-513", 1024, 513},
		{"4096-2049", 4096, 2049},
		{"256-171", 256, 171},
		{"1024-683", 1024, 683},
		{"4096-2731", 4096, 2731},
	}

	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte{})

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {

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

			msig := m.combine(signers, sigmas)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.gverify(roMsg, msig)
			}
		})
	}
}
