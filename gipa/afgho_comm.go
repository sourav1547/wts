package wts

// TODO: To import a hash function to use it as a CRS
import (
	"encoding/binary"
	"fmt"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type AFGHO struct {
	n      int
	key_g1 []bls.G2Affine
	key_g2 []bls.G1Affine
}

// Function to generate crs
func NewAFGHO(n int) AFGHO {
	var (
		dest []byte
		src  []byte
	)
	key_g1 := make([]bls.G2Affine, n)
	key_g2 := make([]bls.G1Affine, n)

	for i := 0; i < n; i++ {
		// To double check this, this might throw an error
		binary.LittleEndian.PutUint32(src, uint32(i))
		key_g1[i], _ = bls.HashToG2(src, dest)
		key_g2[i], _ = bls.HashToG1(src, dest)
	}

	return AFGHO{
		n:      n,
		key_g1: key_g1,
		key_g2: key_g2,
	}
}

func (a *AFGHO) commit_g1(vec []bls.G1Affine) bls.GT {
	res, err := bls.Pair(vec, a.key_g1)
	if err != nil {
		fmt.Println("Error computing afgho commitment g1")
		return bls.GT{}
	}
	return res
}

func (a *AFGHO) commit_g2(vec []bls.G2Affine) bls.GT {
	res, err := bls.Pair(a.key_g2, vec)
	if err != nil {
		fmt.Println("Error computing afgho commitment g1")
		return bls.GT{}
	}
	return res
}
