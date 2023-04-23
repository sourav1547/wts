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

func BenchmarkBLSCombineUW(b *testing.B) {
	testCases := []struct {
		name string
		n, t int
	}{
		{"256-129", 256, 128},
		{"1024-513", 1024, 512},
		{"4096-2049", 4096, 2048},
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

			crs := GenBLSCRS(tc.n)
			m := NewBLS(tc.n, tc.t, crs)

			// Picking the first t nodes as things are unweighted
			signers := make([]int, tc.t+1)
			sigmas := make([]bls.G2Jac, tc.t+1)
			for i := 0; i < tc.t+1; i++ {
				signers[i] = i
				sigmas[i] = m.psign(msg, m.pp.signers[i])
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sigmasAff := make([]bls.G2Affine, len(signers))
				for ii, sigma := range sigmas {
					sigmasAff[ii].FromJacobian(&sigma)
				}
				m.combine(signers, sigmasAff)
			}
		})
	}
}

func BenchmarkBLSVerifyUW(b *testing.B) {
	testCases := []struct {
		name string
		n, t int
	}{
		{"256-129", 256, 128},
		{"1024-513", 1024, 512},
		{"4096-2049", 4096, 2048},
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

			crs := GenBLSCRS(tc.n)
			m := NewBLS(tc.n, tc.t, crs)

			// Picking the first t nodes as things are unweighted
			signers := make([]int, tc.t+1)
			sigmas := make([]bls.G2Jac, tc.t+1)
			for i := 0; i < tc.t+1; i++ {
				signers[i] = i
				sigmas[i] = m.psign(msg, m.pp.signers[i])
			}

			sigmasAff := make([]bls.G2Affine, len(signers))
			for ii, sigma := range sigmas {
				sigmasAff[ii].FromJacobian(&sigma)
			}
			sigma := m.combine(signers, sigmasAff)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.gverify(roMsg, sigma)
			}
		})
	}
}
