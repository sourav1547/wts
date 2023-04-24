package compactcert

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func randBytes() []byte {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func ParentHash(l, r []byte) []byte {
	return Hash(append(l, r...))
}

func Hash(b []byte) []byte {
	h := sha3.Sum256(b)
	return h[:]
}

func HashHex(s string) []byte {
	return Hash(HexToBytes(s))
}

func HexToBytes(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func TreeString(data [][][]byte) (s string) {
	for i, level := range data {
		lvlStr := strings.Repeat(" ", (1<<i)*3+i)
		for _, h := range level {
			lvlStr += fmt.Sprintf("%x", h[:3])
			if i > 0 {
				lvlStr += strings.Repeat(" ", (1<<i)*(6+1)-6)
			} else {
				lvlStr += " "
			}
		}
		s = lvlStr + "\n" + s
	}
	return
}

func LayerString(data [][]byte) (s string) {
	for _, h := range data {
		if len(h) > 2 {
			s += fmt.Sprintf("%x ", h[:3])
		} else {
			s += fmt.Sprintf("%x ", h)
			s += strings.Repeat(" ", 6-2*len(h))
		}
	}
	return
}

func TestNewMerkleTree(t *testing.T) {
	for _, test := range []struct {
		name     string
		data     [][]byte
		treeData [][][]byte
	}{
		{
			name: "simple",
			data: [][]byte{HexToBytes("1234"), HexToBytes("5678")},
			treeData: [][][]byte{
				{HashHex("1234"), HashHex("5678")},
				{ParentHash(HashHex("1234"), HashHex("5678"))},
			},
		},
		{
			name: "odd",
			data: [][]byte{HexToBytes("1234"), HexToBytes("5678"), HexToBytes("9abc")},
			treeData: [][][]byte{
				{HashHex("1234"), HashHex("5678"), HashHex("9abc")},
				{ParentHash(HashHex("1234"), HashHex("5678")), Hash(HashHex("9abc"))},
				{ParentHash(ParentHash(HashHex("1234"), HashHex("5678")), Hash(HashHex("9abc")))},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tree := NewMerkleTree().Build(test.data)
			if !reflect.DeepEqual(tree.hashes, test.treeData) {
				t.Errorf("got \n%s\nwant\n%s", TreeString(tree.hashes), TreeString(test.treeData))
			}
		})
	}
}

func TestMerkleTree_Prove(t *testing.T) {
	for _, test := range []struct {
		name      string
		data      [][]byte
		positions []int
		proof     [][]byte
	}{
		{
			name:      "simple",
			data:      [][]byte{HexToBytes("1234"), HexToBytes("5678")},
			positions: []int{0},
			proof:     [][]byte{HashHex("5678")},
		},
		{
			name:      "simple_odd",
			data:      [][]byte{HexToBytes("1234"), HexToBytes("5678"), HexToBytes("9abc")},
			positions: []int{0},
			proof:     [][]byte{HashHex("5678"), Hash(HashHex("9abc"))},
		},
		{
			name:      "big",
			data:      [][]byte{HexToBytes("1234"), HexToBytes("5678"), HexToBytes("9abc"), HexToBytes("def"), HexToBytes("fed"), HexToBytes("cba9"), HexToBytes("8765"), HexToBytes("4321")},
			positions: []int{0, 2, 4, 6},
			proof:     [][]byte{HashHex("5678"), HashHex("def"), HashHex("cba9"), HashHex("4321")},
		},
		{
			name:      "big_odd",
			data:      [][]byte{HexToBytes("1234"), HexToBytes("5678"), HexToBytes("9abc"), HexToBytes("def"), HexToBytes("fed"), HexToBytes("cba9"), HexToBytes("8765")},
			positions: []int{0, 2, 4, 6},
			proof:     [][]byte{HashHex("5678"), HashHex("def"), HashHex("cba9"), []byte{}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tree := NewMerkleTree().Build(test.data)
			t.Log("\n" + TreeString(tree.hashes))
			proof, err := tree.Prove(test.positions)
			if err != nil {
				t.Fatal(err)
			}
			require.ElementsMatchf(t, proof, test.proof, "got %s, want %s", LayerString(proof), LayerString(test.proof))
			elems := make(map[int][]byte)
			for _, pos := range test.positions {
				elems[pos] = Hash(test.data[pos])
			}
			require.NoError(t, VerifyMerkleTree(tree.Root(), elems, proof))
		})
	}
}

func TestMerkle(t *testing.T) {
	junk := randBytes()

	for sz := 2; sz < 1024; sz++ {
		data := make([][]byte, sz)
		for i := 0; i < sz; i++ {
			data[i] = randBytes()
		}

		tree := NewMerkleTree().Build(data)
		root := tree.Root()

		allpos := make([]int, 0, sz)
		allmap := make(map[int][]byte)

		for i := 0; i < sz; i++ {
			proof, err := tree.Prove([]int{i})
			if err != nil {
				t.Fatal(err)
			}

			require.NoError(t, VerifyMerkleTree(root, map[int][]byte{i: Hash(data[i])}, proof), "failed to verify")

			require.Error(t, VerifyMerkleTree(root, map[int][]byte{i: Hash(junk)}, proof), "no error when verifying junk")

			allpos = append(allpos, i)
			allmap[i] = Hash(data[i])
		}

		proof, err := tree.Prove(allpos)
		if err != nil {
			t.Fatal(err)
		}
		require.NoError(t, VerifyMerkleTree(root, allmap, proof), "failed to verify batch")

		require.Error(t, VerifyMerkleTree(root, map[int][]byte{0: Hash(junk)}, proof), "no error when verifying junk batch")

		require.Error(t, VerifyMerkleTree(root, map[int][]byte{0: Hash(junk)}, nil), "no error when verifying nil proof")

		_, err = tree.Prove([]int{sz})
		if err == nil {
			t.Fatalf("no error when proving past the end")
		}

		require.Error(t, VerifyMerkleTree(root, map[int][]byte{sz: Hash(junk)}, nil), "no error when verifying past the end")

		if sz > 0 {
			var somepos []int
			somemap := make(map[int][]byte)
			for i := 0; i < 10; i++ {
				pos := rand.Int() % sz
				somepos = append(somepos, pos)
				somemap[pos] = Hash(data[pos])
			}

			proof, err = tree.Prove(somepos)
			if err != nil {
				t.Fatal(err)
			}

			require.NoError(t, VerifyMerkleTree(root, somemap, proof), "failed to verify batch")
		}
	}
}

func BenchmarkMerkleCommit(b *testing.B) {
	for sz := 10; sz <= 100000; sz *= 100 {
		msg := randBytes()

		for cnt := 10; cnt <= 10000000; cnt *= 10 {
			a := make([]byte, len(msg))
			copy(a, msg)
			binary.LittleEndian.PutUint64(a, uint64(cnt))

			b.Run(fmt.Sprintf("Item%d/Count%d", sz, cnt), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					tree := NewMerkleTree().Build([][]byte{a})
					tree.Root()
				}
			})
		}
	}
}

// func BenchmarkMerkleProve1M(b *testing.B) {
// 	msg := TestMessage("Hello world")

// 	var a TestRepeatingArray
// 	a.item = msg
// 	a.count = 1024 * 1024

// 	tree, err := Build(a)
// 	if err != nil {
// 		b.Error(err)
// 	}

// 	b.ResetTimer()

// 	for i := uint64(0); i < uint64(b.N); i++ {
// 		_, err := tree.Prove([]uint64{i % a.count})
// 		if err != nil {
// 			b.Error(err)
// 		}
// 	}
// }

// func BenchmarkMerkleVerify1M(b *testing.B) {
// 	msg := TestMessage("Hello world")

// 	var a TestRepeatingArray
// 	a.item = msg
// 	a.count = 1024 * 1024

// 	tree, err := Build(a)
// 	if err != nil {
// 		b.Error(err)
// 	}
// 	root := tree.Root()

// 	proofs := make([][]crypto.Digest, a.count)
// 	for i := uint64(0); i < a.count; i++ {
// 		proofs[i], err = tree.Prove([]uint64{i})
// 		if err != nil {
// 			b.Error(err)
// 		}
// 	}

// 	b.ResetTimer()

// 	for i := uint64(0); i < uint64(b.N); i++ {
// 		err := Verify(root, map[uint64]crypto.Digest{i % a.count: crypto.HashObj(msg)}, proofs[i])
// 		if err != nil {
// 			b.Error(err)
// 		}
// 	}
// }
