package compactcert

import (
	"bytes"
	"fmt"
	"hash"
	"runtime"
	"sort"
	"sync"

	"golang.org/x/crypto/sha3"
)

type MerkleTree struct {
	newHasher func() hash.Hash
	hashes    [][][]byte
}

type proofItem struct {
	idx  int
	hash []byte
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func NewMerkleTree() *MerkleTree {
	return &MerkleTree{newHasher: sha3.New256, hashes: make([][][]byte, 0)}
}

func (mt *MerkleTree) WithHasher(f func() hash.Hash) *MerkleTree {
	mt.newHasher = f
	return mt
}

func HashSum(h hash.Hash, data ...[]byte) []byte {
	for _, d := range data {
		h.Write(d)
	}
	sum := h.Sum(nil)
	h.Reset()
	return sum
}

func (mt *MerkleTree) Build(data [][]byte) *MerkleTree {
	// Concurrently hash leaves
	mt.hashes = append(mt.hashes, make([][]byte, len(data)))
	wg := sync.WaitGroup{}
	batchSize := len(data) / runtime.NumCPU()
	if batchSize == 0 {
		batchSize = len(data)
	}
	for i := 0; i < len(data); i += batchSize {
		wg.Add(1)
		go func(from, to int) {
			defer wg.Done()
			h := mt.newHasher()
			for j := from; j < to; j++ {
				mt.hashes[0][j] = HashSum(h, data[j])
			}
		}(i, min(i+batchSize, len(data)))
	}
	wg.Wait()

	// Concurrently hash internal nodes
	for i := 1; len(mt.hashes[len(mt.hashes)-1]) > 1; i++ {
		mt.hashes = append(mt.hashes, make([][]byte, (len(mt.hashes[i-1])+1)/2))
		wg := sync.WaitGroup{}
		batchSize := len(mt.hashes[i]) / runtime.NumCPU()
		if batchSize == 0 {
			batchSize = len(mt.hashes[i])
		}
		for j := 0; j < len(mt.hashes[i]); j += batchSize {
			wg.Add(1)
			go func(i, from, to int) {
				defer wg.Done()
				h := mt.newHasher()
				for k := from; k < to; k++ {
					h.Write(mt.hashes[i-1][2*k])
					if 2*k+1 < len(mt.hashes[i-1]) {
						h.Write(mt.hashes[i-1][2*k+1])
					}
					mt.hashes[i][k] = h.Sum(nil)
					h.Reset()
				}
			}(i, j, min(j+batchSize, len(mt.hashes[i])))
		}
		wg.Wait()
	}
	return mt
}

func (mt *MerkleTree) Root() []byte {
	if len(mt.hashes) == 0 || len(mt.hashes[0]) == 0 {
		return nil
	}
	return mt.hashes[len(mt.hashes)-1][0]
}

func (mt *MerkleTree) Prove(idxs []int) ([][]byte, error) {
	proof := make([][]byte, 0)

	knownIdxs := make([]int, len(idxs))
	copy(knownIdxs, idxs)
	sort.Ints(knownIdxs)
	for i := len(knownIdxs) - 1; i >= 0; i-- {
		idx := knownIdxs[i]
		if idx < 0 || idx >= len(mt.hashes[0]) {
			return nil, fmt.Errorf("invalid index %d", idx)
		}
		if i > 0 && idx == knownIdxs[i-1] {
			// Duplicate index
			knownIdxs = append(knownIdxs[:i], knownIdxs[i+1:]...)
		}
	}

	for j := 0; j < len(mt.hashes)-1; j++ {
		newKnownIdxs := make([]int, 0, (len(knownIdxs)+1)/2)
		for i := 0; i < len(knownIdxs); i++ {
			idx := knownIdxs[i]
			if idx%2 == 0 {
				// Left child
				if i+1 < len(knownIdxs) && idx+1 == knownIdxs[i+1] {
					// Already know the sibling, skip it
					i++
				} else {
					if idx+1 < len(mt.hashes[j]) {
						proof = append(proof, mt.hashes[j][idx+1])
					} else {
						// Odd level, right sibling is non-existent
						proof = append(proof, []byte{})
					}
				}
			} else {
				// Right child, already know left sibling is not in proof, so add it
				proof = append(proof, mt.hashes[j][idx-1])
			}
			newKnownIdxs = append(newKnownIdxs, idx/2)
		}
		knownIdxs = newKnownIdxs
	}

	return proof, nil
}

func VerifyMerkleTree(root []byte, elems map[int][]byte, proof [][]byte) error {
	return VerifyMerkleTreeWithHash(sha3.New256(), root, elems, proof)
}

func VerifyMerkleTreeWithHash(h hash.Hash, root []byte, elems map[int][]byte, proof [][]byte) error {
	if len(elems) == 0 {
		return nil
	}

	// Sort the proof items by index
	partialLayer := make([]proofItem, 0, len(elems))
	for i, h := range elems {
		if i < 0 {
			return fmt.Errorf("invalid index %d", i)
		}
		partialLayer = append(partialLayer, proofItem{i, h})
	}
	sort.Slice(partialLayer, func(i, j int) bool { return partialLayer[i].idx < partialLayer[j].idx })

	// Verify the proof
	pID := 0
	for !bytes.Equal(partialLayer[0].hash, root) {
		nextPartialLayer := make([]proofItem, 0, (len(partialLayer)+1)/2)
		for i := 0; i < len(partialLayer); i++ {
			p := partialLayer[i]
			var left, right []byte
			if p.idx%2 == 0 {
				left = p.hash
				if i+1 < len(partialLayer) && p.idx+1 == partialLayer[i+1].idx {
					right = partialLayer[i+1].hash
					i++
				} else {
					if pID >= len(proof) {
						return fmt.Errorf("invalid proof")
					}
					right = proof[pID]
					pID++
				}
			} else {
				if pID >= len(proof) {
					return fmt.Errorf("invalid proof")
				}
				right = p.hash
				left = proof[pID]
				pID++
			}
			nextPartialLayer = append(nextPartialLayer, proofItem{p.idx / 2, HashSum(h, left, right)})
		}
		partialLayer = nextPartialLayer
	}
	return nil
}
