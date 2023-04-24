package compactcert

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/signature"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"golang.org/x/exp/constraints"
)

func NewSlice[T constraints.Integer | constraints.Float](start T, count int, step T) []T {
	s := make([]T, count)
	for i := range s {
		s[i] = start
		start += step
	}
	return s
}

func TestBuildVerify(t *testing.T) {
	totalWeight := 100_000
	npartHi := 1_000
	npartLo := 9_000
	npart := npartHi + npartLo

	param := Params{
		Msg:          []byte("hello world"),
		ProvenWeight: uint64(totalWeight / 2),
		SecKQ:        128,
	}

	// Share the key; we allow the same vote key to appear in multiple accounts..
	signer, err := GenerateSchnorrSigner(rand.Reader)
	require.NoError(t, err)

	var parts Participants
	sigs := make([][]byte, 0, npart)
	for i := 0; i < npartHi; i++ {
		part := Participant{
			PK:     signer.Public(),
			Weight: uint64(totalWeight / 2 / npartHi),
		}

		parts = append(parts, part)
	}

	for i := 0; i < npartLo; i++ {
		part := Participant{
			PK:     signer.Public(),
			Weight: uint64(totalWeight / 2 / npartLo),
		}

		parts = append(parts, part)
	}

	hFunc := sha3.New256()
	sig, err := signer.Sign(param.Msg, hFunc)
	require.NoError(t, err)
	for i := 0; i < npart; i++ {
		sigs = append(sigs, sig)
	}

	var partcom *MerkleTree
	if partsb, err := parts.Bytes(); err == nil {
		partcom = NewMerkleTree().Build(partsb)
	} else {
		t.Fatal(err)
	}

	b := NewBuilder(param, parts, partcom)

	for i := 0; i < npart; i++ {
		require.NoError(t, b.AddSignature(i, sigs[i]))
	}

	cert, err := b.Build()
	require.NoError(t, err)

	var someRevealSize, someRevealSigSize, sigProofsSize int
	for _, rev := range cert.Reveals {
		someRevealSize = int(rev.Size())

		someRevealSigSlotEnc, err := rev.SigSlot.MarshalBinary()
		require.NoError(t, err)
		someRevealSigSize = len(someRevealSigSlotEnc)
		break
	}
	for _, sigProof := range cert.SigProofs {
		sigProofsSize += len(sigProof)
	}

	fmt.Printf("Cert size:\n")
	fmt.Printf("  %6d elems sigproofs\n", len(cert.SigProofs))
	fmt.Printf("  %6d bytes sigproofs\n", sigProofsSize)
	// fmt.Printf("  %6d bytes partproofs\n", len(protocol.EncodeReflect(cert.PartProofs)))
	fmt.Printf("  %6d bytes sigproof per reveal\n", sigProofsSize/len(cert.Reveals))
	fmt.Printf("  %6d reveals:\n", len(cert.Reveals))
	// fmt.Printf("    %6d bytes reveals[*] participant\n", len(protocol.Encode(&someReveal.Part)))
	fmt.Printf("    %6d bytes reveals[*] sigslot\n", someRevealSigSize)
	fmt.Printf("    %6d bytes reveals[*] total\n", someRevealSize)
	fmt.Printf("  %6d bytes total\n", cert.Size())

	verif := NewVerifier(param, partcom.Root())
	err = verif.Verify(cert)
	require.NoError(t, err)
}

func BenchmarkBuildVerify(b *testing.B) {
	// for _, npart := range []int{256, 1024, 4096} {
	// 	for _, threshold := range []int{npart / 2, 2 * npart / 3} {
	// 		b.Run(fmt.Sprintf("npart=%d/threshold=%d/unweighted", npart, threshold), func(b *testing.B) {
	// 			benchBuildVerify(b, npart, threshold, func(i uint64) uint64 { return 1 })
	// 		})
	// 	}
	// }
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"256-129", 256, 129},
		{"1024-513", 1024, 513},
		{"4096-2049", 4096, 2049},
		{"256-171", 256, 171},
		{"1024-683", 1024, 683},
		{"4096-2731", 4096, 2731},
	} {
		b.Run(tc.name, func(b *testing.B) {
			benchBuildVerify(b, tc.n, tc.t, func(i uint64) uint64 { return 1 })
		})
	}
}

func benchBuildVerify(b *testing.B, npart, threshold int, weight func(i uint64) uint64) {
	param := Params{
		Msg:          []byte("hello world"),
		ProvenWeight: uint64(threshold),
		SecKQ:        128,
	}
	collectWeight := uint64(5 * threshold / 4)

	var parts Participants
	var partkeys []signature.Signer
	var sigs [][]byte
	hFunc := sha3.New256()

	for i := 0; i < npart; i++ {
		signer, err := GenerateSchnorrSigner(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		part := Participant{
			PK:     signer.Public(),
			Weight: weight(uint64(i)),
		}

		sig, err := signer.Sign(param.Msg, hFunc)
		if err != nil {
			b.Fatal(err)
		}

		partkeys = append(partkeys, signer)
		sigs = append(sigs, sig)
		parts = append(parts, part)
	}

	var (
		cert    *Cert
		partcom *MerkleTree
		err     error
	)
	if partsb, err := parts.Bytes(); err == nil {
		partcom = NewMerkleTree().Build(partsb)
	} else {
		b.Fatal(err)
	}

	b.Run("AddBuild", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			builder := NewBuilder(param, parts, partcom)
			for i := 0; i < npart && builder.signedWeight < uint64(collectWeight); i++ {
				require.NoError(b, builder.AddSignature(i, sigs[i]))
			}
			// b.StartTimer()
			cert, err = builder.Build()
			require.NoError(b, err)

			b.ReportMetric(float64(cert.Size()), "certsize/op")
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			verif := NewVerifier(param, partcom.Root())
			require.NoError(b, verif.Verify(cert))
		}
	})
}

// Below is a modification of the go-algorand compact certificate benchmark
// to work with the go-algorand codebase directly. Mimics similar behavior
// to above benchmark but with go-algorand codebase.
// https://github.com/algorand/go-algorand/blob/ade1fead41c1dc298fc7c7640137d37825e1a7ae/crypto/compactcert/builder_test.go
//
// func BenchmarkBuildVerify(b *testing.B) {
// 	for _, threshold := range []int{256, 1024, 4096} {
// 		b.Run(fmt.Sprintf("t=%d", threshold), func(b *testing.B) {
// 			benchBuildVerify(b, 2*threshold, threshold, func(i uint64) uint64 { return 1 })
// 		})
// 	}
// }

// func benchBuildVerify(b *testing.B, npart, threshold int, weight func(i uint64) uint64) {
// 	param := Params{
// 		Msg:          TestMessage("hello world"),
// 		ProvenWeight: uint64(threshold),
// 		SecKQ:        128,
// 	}
// 	collectWeight := uint64(5 * threshold / 4)

// 	var parts []Participant
// 	var partkeys []*crypto.OneTimeSignatureSecrets
// 	var sigs []crypto.OneTimeSignature

// 	for i := 0; i < npart; i++ {
// 		key := crypto.GenerateOneTimeSignatureSecrets(0, 1)
// 		part := Participant{
// 			PK:          key.OneTimeSignatureVerifier,
// 			Weight:      weight(uint64(i)),
// 			KeyDilution: 10000,
// 		}

// 		ephID := basics.OneTimeIDForRound(0, part.KeyDilution)
// 		sig := key.Sign(ephID, param.Msg)

// 		partkeys = append(partkeys, key)
// 		sigs = append(sigs, sig)
// 		parts = append(parts, part)
// 	}

// 	var cert *Cert
// 	partcom, err := merklearray.Build(PartCommit{parts})
// 	require.NoError(b, err)

// 	b.Run("AddBuild", func(b *testing.B) {
// 		for i := 0; i < b.N; i++ {
// 			builder, err := MkBuilder(param, parts, partcom)
// 			require.NoError(b, err)
// 			for i := 0; i < npart && builder.signedWeight < uint64(collectWeight); i++ {
// 				require.NoError(b, builder.Add(uint64(i), sigs[i], true))
// 			}
// 			// b.StartTimer()
// 			cert, err = builder.Build()
// 			require.NoError(b, err)

// 			b.ReportMetric(float64(len(protocol.Encode(cert))), "certsizeB/op")
// 		}
// 	})

// 	b.Run("Verify", func(b *testing.B) {
// 		for i := 0; i < b.N; i++ {
// 			verif := MkVerifier(param, partcom.Root())
// 			require.NoError(b, verif.Verify(cert))
// 		}
// 	})
// }

func TestCoinIndex(t *testing.T) {
	n := 1000
	b := &Builder{
		participants: make([]Participant, n),
		sigs:         make([]sigSlot, n),
	}

	for i := 0; i < n; i++ {
		b.sigs[i].L = uint64(i)
		b.participants[i].Weight = 1
	}

	for i := 0; i < n; i++ {
		pos, err := b.coinIndex(uint64(i))
		require.NoError(t, err)
		require.Equal(t, pos, uint64(i))
	}
}
