package wts

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	"bytes"
	"os"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"

	//"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

const NUM_NODES = 8 // Indicates the number of signers

type mtsCircuit struct {
	curveID      tedwards.ID
	PublicKeys   [NUM_NODES]PublicKey `gnark:",public"`
	Signatures   [NUM_NODES]Signature `gnark:",public"`
	Message      frontend.Variable    `gnark:",public"`
	RootHash     frontend.Variable    `gnark:",public"`
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
	snarkCurve := ecc.BLS12_381

	seed := time.Now().Unix()
	t.Logf("setting seed in rand %d", seed)
	randomness := rand.New(rand.NewSource(seed))

	var privKeys [NUM_NODES]signature.Signer

	snarkField, err := twistededwards.GetSnarkField(conf.curve)
	assert.NoError(err)
	var msg big.Int
	msg.Rand(randomness, snarkField)
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
		// t.Logf("verified merkle proof")

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

	// assert.ProverSucceeded(&circuit, &witness, test.WithCurves(snarkCurve), test.WithBackends(backend.PLONK), test.NoFuzzing(), test.NoSerialization())
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(snarkCurve), test.WithBackends(backend.GROTH16), test.NoFuzzing(), test.NoSerialization())
}

func BenchmarkSNARK(b *testing.B) {
	type testData struct {
		hash  hash.Hash
		curve tedwards.ID
	}

	conf := testData{hash.MIMC_BLS12_381, tedwards.BLS12_381}
	snarkCurve := ecc.BLS12_381

	seed := time.Now().Unix()
	randomness := rand.New(rand.NewSource(seed))

	var privKeys [NUM_NODES]signature.Signer

	snarkField, _ := twistededwards.GetSnarkField(conf.curve)

	var msg big.Int
	msg.Rand(randomness, snarkField)
	msgData := msg.Bytes()

	// create and compile the circuit for signature verification
	var circuit mtsCircuit
	circuit.curveID = conf.curve

	var witness mtsCircuit
	witness.Message = msg

	for i := 0; i < NUM_NODES; i++ {
		// generate parameters for the signatures
		privKey, _ := eddsa.New(conf.curve, randomness)
		privKeys[i] = privKey

		// generate signature
		signature, _ := privKey.Sign(msgData[:], conf.hash.New())
		pubKey := privKey.Public()

		witness.PublicKeys[i].Assign(snarkCurve, pubKey.Bytes())
		witness.Signatures[i].Assign(snarkCurve, signature)
	}

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
			os.Exit(-1)
		}
		proofHelper := GenerateProofHelper(proof, proofIndex, numLeaves)

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

	fwitness, _ := frontend.NewWitness(&witness, ecc.BLS12_381.ScalarField())
	publicWitness, _ := fwitness.Public()

	// Testing plonk
	ccsp, _ := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	srs, _ := test.NewKZGSRS(ccsp)
	pkp, vkp, _ := plonk.Setup(ccsp, srs)
	var pfp plonk.Proof
	b.Run("plonk-prove", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pfp, _ = plonk.Prove(ccsp, pkp, fwitness)
		}
	})

	b.Run("plonk-verify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			plonk.Verify(pfp, vkp, publicWitness)
		}
	})

	// Testing groth16
	ccsg, _ := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	pkg, vkg, _ := groth16.Setup(ccsg)
	var pfg groth16.Proof
	b.Run("groth16-prove", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pfg, _ = groth16.Prove(ccsg, pkg, fwitness)
		}
	})

	b.Run("groth16-verify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			groth16.Verify(pfg, vkg, publicWitness)
		}
	})
}
