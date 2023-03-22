package compactcert

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
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
	totalWeight := 10_000_000
	npartHi := 1_000
	npartLo := 990_000
	npart := npartHi + npartLo

	param := Params{
		Msg:          []byte("hello world"),
		ProvenWeight: uint64(totalWeight / 2),
		SecKQ:        128,
	}

	// Share the key; we allow the same vote key to appear in multiple accounts..
	signer := NewBLSSigner()

	var parts Participants[BLSPubKey]
	var sigs [][]byte
	for i := 0; i < npartHi; i++ {
		part := Participant[BLSPubKey]{
			PK:     signer.BLSPubKey,
			Weight: uint64(totalWeight / 2 / npartHi),
		}

		parts = append(parts, part)
	}

	for i := 0; i < npartLo; i++ {
		part := Participant[BLSPubKey]{
			PK:     signer.BLSPubKey,
			Weight: uint64(totalWeight / 2 / npartLo),
		}

		parts = append(parts, part)
	}

	sig, err := signer.Sign(param.Msg)
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

	b := NewBuilder(param, parts, partcom).WithBatchVerifier(BLSBatchVerifier)

	err = b.AddSignatures(NewSlice(0, npart, 1), sigs)
	require.NoError(t, err)

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

	verif := NewVerifier[BLSPubKey](param, partcom.Root()).WithBatchVerifier(BLSBatchVerifier)
	err = verif.Verify(cert)
	require.NoError(t, err)
}

func BenchmarkBuildVerify(b *testing.B) {
	totalWeight := 1000000
	npart := 10000

	param := Params{
		Msg:          []byte("hello world"),
		ProvenWeight: uint64(totalWeight / 2),
		SecKQ:        128,
	}

	var parts Participants[BLSPubKey]
	var partkeys []Signer
	var sigs [][]byte
	for i := 0; i < npart; i++ {
		signer := NewBLSSigner()
		part := Participant[BLSPubKey]{
			PK:     signer.BLSPubKey,
			Weight: uint64(totalWeight / npart),
		}

		sig, err := signer.Sign(param.Msg)
		if err != nil {
			b.Fatal(err)
		}

		partkeys = append(partkeys, signer)
		sigs = append(sigs, sig)
		parts = append(parts, part)
	}

	var (
		cert    *Cert[BLSPubKey]
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
			builder := NewBuilder(param, parts, partcom).WithBatchVerifier(BLSBatchVerifier)
			require.NoError(b, builder.AddSignatures(NewSlice(0, npart, 1), sigs))
			// b.StartTimer()
			cert, err = builder.Build()
			require.NoError(b, err)

			b.ReportMetric(float64(cert.Size()), "certsize/op")
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			verif := NewVerifier[BLSPubKey](param, partcom.Root()).WithBatchVerifier(BLSBatchVerifier)
			require.NoError(b, verif.Verify(cert))
		}
	})
}

func TestCoinIndex(t *testing.T) {
	n := 1000
	b := &Builder[BLSPubKey]{
		participants: make([]Participant[BLSPubKey], n),
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
