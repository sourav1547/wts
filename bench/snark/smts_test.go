package wts

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	"bytes"
	"os"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	//"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

const NUM_NODES = 4

type mtsCircuit struct {
	curveID      tedwards.ID
	PublicKeys   [NUM_NODES]PublicKey `gnark:",public"`
	Signatures   [NUM_NODES]Signature `gnark:",public"`
	Weights      [NUM_NODES]int       `gnark:",public"`
	Message      frontend.Variable    `gnark:",public"`
	RootHash     frontend.Variable    `gnark:",public"`
	threshold    int                  `gnark:",public"`
	Path, Helper [][]frontend.Variable
}

func (circuit *mtsCircuit) Define(api frontend.API) error {

	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	eddsa_hasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	merkle_hasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	VerifyProofs(api, merkle_hasher, circuit.RootHash, circuit.Path, circuit.Helper)
	// verify the signature in the cs
	return Verify(curve, circuit.Signatures, circuit.Message, circuit.PublicKeys, &eddsa_hasher)
}

func TestMts(t *testing.T) {

	assert := test.NewAssert(t)

	type testData struct {
		hash  hash.Hash
		curve tedwards.ID
	}

	conf := testData{hash.MIMC_BLS12_381, tedwards.BLS12_381}

	seed := time.Now().Unix()
	t.Logf("setting seed in rand %d", seed)
	randomness := rand.New(rand.NewSource(seed))

	var privKeys [NUM_NODES]signature.Signer

	snarkCurve, err := twistededwards.GetSnarkCurve(conf.curve)
	assert.NoError(err)

	// pick a message to sign
	var msg big.Int
	msg.Rand(randomness, snarkCurve.Info().Fr.Modulus())
	t.Log("msg to sign", msg.String())
	msgData := msg.Bytes()

	// create and compile the circuit for signature verification
	var circuit mtsCircuit
	circuit.curveID = conf.curve

	var witness mtsCircuit
	witness.Message = msg

	for i := 0; i < NUM_NODES; i++ {
		// generate parameters for the signatures
		privKey, err := eddsa.New(conf.curve, randomness)
		assert.NoError(err, "generating eddsa key pair")
		privKeys[i] = privKey

		// generate signature
		signature, err := privKey.Sign(msgData[:], conf.hash.New())
		assert.NoError(err, "signing message")

		// check if there is no problem in the signature
		pubKey := privKey.Public()
		checkSig, err := pubKey.Verify(signature, msgData[:], conf.hash.New())
		assert.NoError(err, "verifying signature")
		assert.True(checkSig, "signature verification failed")

		witness.PublicKeys[i].Assign(snarkCurve, pubKey.Bytes())
		witness.Signatures[i].Assign(snarkCurve, signature)

	}
	t.Log("verified correct signatures")

	numProofs := NUM_NODES
	circuit.Path = make([][]frontend.Variable, numProofs)
	circuit.Helper = make([][]frontend.Variable, numProofs)

	witness.Path = make([][]frontend.Variable, numProofs)
	witness.Helper = make([][]frontend.Variable, numProofs)

	for id := 0; id < numProofs; id++ {
		// build a merkle tree -- todo: check use of hashing here
		var buf bytes.Buffer
		for i := 0; i < NUM_NODES; i++ {
			var leaf fr.Element
			leaf.SetBytes(privKeys[i].Public().Bytes())
			b := leaf.Bytes()
			buf.Write(b[:])
		}

		// build & verify proof for an elmt in the file
		proofIndex := uint64(id)
		segmentSize := 32
		merkleRoot, proof, numLeaves, err := merkletree.BuildReaderProof(&buf, bls12381.NewMiMC(), segmentSize, proofIndex)
		if err != nil {
			t.Fatal(err)
			os.Exit(-1)
		}
		proofHelper := GenerateProofHelper(proof, proofIndex, numLeaves)

		verified := merkletree.VerifyProof(bls12381.NewMiMC(), merkleRoot, proof, proofIndex, numLeaves)
		if !verified {
			t.Fatal("The merkle proof in plain go should pass")
		}
		t.Logf("verified merkle proof")

		witness.RootHash = merkleRoot
		witness.Path[id] = make([]frontend.Variable, len(proof))
		witness.Helper[id] = make([]frontend.Variable, len(proof)-1)
		for i := 0; i < len(proof); i++ {
			witness.Path[id][i] = (proof[i])
		}
		for i := 0; i < len(proof)-1; i++ {
			witness.Helper[id][i] = (proofHelper[i])
		}

		circuit.Path[id] = make([]frontend.Variable, len(proof))
		circuit.Helper[id] = make([]frontend.Variable, len(proof)-1)
	}

	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(snarkCurve))
	// assert.ProverFailed(&circuit, &witness, test.WithCurves(snarkCurve))
	// assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(snarkCurve))
}
