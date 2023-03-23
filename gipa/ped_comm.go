package wts

// TODO: To import a hash function to use it as a CRS
import (
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type Ped struct {
	n    int
	keys []bls.G1Affine
}

// Function to generate pedersen CRS
func NewPed(n int) Ped {
	var (
		dest []byte
		src  []byte
	)
	keys := make([]bls.G1Affine, n)

	for i := 0; i < n; i++ {
		// To double check this, this might throw an error
		binary.LittleEndian.PutUint32(src, uint32(i))
		keys[i], _ = bls.HashToCurveG1SSWU(src, dest)
	}

	return Ped{
		n:    n,
		keys: keys,
	}
}

func (a *Ped) commit(vec []fr.Element) bls.G1Jac {
	var comm bls.G1Jac
	res, err := comm.MultiExp(a.keys, vec, ecc.MultiExpConfig{ScalarsMont: true})
	if err != nil {
		fmt.Println("Error computing ped commitment g1")
		return bls.G1Jac{}
	}
	return *res
}
