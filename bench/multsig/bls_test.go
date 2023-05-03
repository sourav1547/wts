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

func BenchmarkBLSUW(b *testing.B) {
	testCases := []struct {
		name string
		n, t int
	}{
		{"64", 64, 64},
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

		crs := GenBLSCRS(tc.n)
		m := NewBLS(tc.n, tc.t-1, crs)

		// Picking the first t nodes as things are unweighted
		signers := make([]int, tc.t)
		sigmas := make([]bls.G2Jac, tc.t)
		for i := 0; i < tc.t; i++ {
			signers[i] = i
			sigmas[i] = m.psign(msg, m.pp.signers[i])
		}

		var sigma bls.G2Jac
		b.Run(tc.name+"-agg", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sigmasAff := make([]bls.G2Affine, len(signers))
				for ii, sigma := range sigmas {
					sigmasAff[ii].FromJacobian(&sigma)
				}
				sigma = m.combine(signers, sigmasAff)
			}
		})

		b.Run(tc.name+"-ver", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.gverify(roMsg, sigma)
			}
		})
	}
}

func BenchmarkBLSLarge(b *testing.B) {
	testCases := []struct {
		name string
		n, t int
	}{
		{"32768", 32768, 32768},
		{"65536", 65536, 65536},
	}

	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte{})

	for _, tc := range testCases {

		weights := make([]int, tc.n)
		for i := 0; i < tc.n; i++ {
			weights[i] = 1
		}

		crs := GenBLSCRS(tc.n)
		m := NewBLS(tc.n, tc.t-1, crs)

		// Picking the first t nodes as things are unweighted
		signers := make([]int, tc.t)
		sigmas := make([]bls.G2Jac, tc.t)
		for i := 0; i < tc.t; i++ {
			signers[i] = i
			sigmas[i] = m.psign(msg, m.pp.signers[i])
		}

		var sigma bls.G2Jac
		b.Run(tc.name+"-agg", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sigmasAff := make([]bls.G2Affine, len(signers))
				for ii, sigma := range sigmas {
					sigmasAff[ii].FromJacobian(&sigma)
				}
				sigma = m.combine(signers, sigmasAff)
			}
		})

		b.Run(tc.name+"-ver", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.gverify(roMsg, sigma)
			}
		})
	}
}
