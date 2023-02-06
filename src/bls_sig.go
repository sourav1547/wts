package wts

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func New() {
	g1j, _, _, _ := bls12381.Generators()
	var g1j2 bls12381.G1Jac
	fmt.Println(g1j)
	fmt.Println(g1j2)

	g1j2.Double(&g1j)
	fmt.Println(g1j2.Equal(g1j.AddAssign(&g1j)))
}
