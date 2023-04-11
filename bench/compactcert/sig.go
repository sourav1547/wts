package compactcert

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"hash"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	secp256k1_ecdsa "github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	secp256k1_fp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	secp256k1_fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark-crypto/signature"
)

const (
	sizeFr         = secp256k1_fr.Bytes
	sizeFp         = secp256k1_fp.Bytes
	sizePublicKey  = 2 * sizeFp
	sizePrivateKey = sizeFr + sizePublicKey
	sizeSignature  = 2 * sizeFr
)

var (
	order = secp256k1_fr.Modulus()
	one   = new(big.Int).SetInt64(1)
)

type zr struct{}

// Read replaces the contents of dst with zeros. It is safe for concurrent use.
func (zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = zr{}

const (
	aesIV = "gnark-crypto IV." // must be 16 chars (equal block size)
)

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.1.
func secp256k1RandFieldElement(rand io.Reader) (k *big.Int, err error) {
	b := make([]byte, fr.Bits/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(order, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func nonce(privateKey []byte, hash []byte) (csprng *cipher.StreamReader, err error) {
	// This implementation derives the nonce from an AES-CTR CSPRNG keyed by:
	//
	//    SHA2-512(privateKey.scalar ∥ entropy ∥ hash)[:32]
	//
	// The CSPRNG key is indifferentiable from a random oracle as shown in
	// [Coron], the AES-CTR stream is indifferentiable from a random oracle
	// under standard cryptographic assumptions (see [Larsson] for examples).
	//
	// [Coron]: https://cs.nyu.edu/~dodis/ps/merkle.pdf
	// [Larsson]: https://web.archive.org/web/20040719170906/https://www.nada.kth.se/kurser/kth/2D1441/semteo03/lecturenotes/assump.pdf

	// Get 256 bits of entropy from rand.
	entropy := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, entropy)
	if err != nil {
		return

	}

	// Initialize an SHA-512 hash context; digest...
	md := sha512.New()
	md.Write(privateKey)    // the private key,
	md.Write(entropy)       // the entropy,
	md.Write(hash)          // and the input hash;
	key := md.Sum(nil)[:32] // and compute ChopMD-256(SHA-512),
	// which is an indifferentiable MAC.

	// Create an AES-CTR instance to use as a CSPRNG.
	block, _ := aes.NewCipher(key)

	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	csprng = &cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	return csprng, err
}

type SchnorrPublicKey struct {
	secp256k1_ecdsa.PublicKey
}

type SchnorrSigner struct {
	SchnorrPublicKey
	scalar [sizeFr]byte // secret scalar, in big Endian
}

// Public returns the public key associated to the private key.
func (privKey *SchnorrSigner) Public() signature.PublicKey {
	var pub SchnorrPublicKey
	pub.A.Set(&privKey.PublicKey.A)
	return &pub
}

// Bytes returns the binary representation of pk,
// as byte array publicKey||scalar
// where publicKey is as publicKey.Bytes(), and
// scalar is in big endian, of size sizeFr.
func (privKey *SchnorrSigner) Bytes() []byte {
	var res [sizePrivateKey]byte
	pubkBin := privKey.PublicKey.A.RawBytes()
	subtle.ConstantTimeCopy(1, res[:sizePublicKey], pubkBin[:])
	subtle.ConstantTimeCopy(1, res[sizePublicKey:sizePrivateKey], privKey.scalar[:])
	return res[:]
}

// SetBytes sets pk from buf, where buf is interpreted
// as  publicKey||scalar
// where publicKey is as publicKey.Bytes(), and
// scalar is in big endian, of size sizeFr.
// It returns the number byte read.
func (privKey *SchnorrSigner) SetBytes(buf []byte) (int, error) {
	n := 0
	if len(buf) < sizePrivateKey {
		return n, io.ErrShortBuffer
	}
	if _, err := privKey.PublicKey.A.SetBytes(buf[:sizePublicKey]); err != nil {
		return 0, err
	}
	n += sizePublicKey
	subtle.ConstantTimeCopy(1, privKey.scalar[:], buf[sizePublicKey:sizePrivateKey])
	n += sizeFr
	return n, nil
}

type SchnorrSignature struct {
	S, E [sizeFr]byte
}

// Bytes returns the binary representation of sig
// as a byte array of size 2*sizeFr r||s
func (sig *SchnorrSignature) Bytes() []byte {
	var res [sizeSignature]byte
	subtle.ConstantTimeCopy(1, res[:sizeFr], sig.S[:sizeFr])
	subtle.ConstantTimeCopy(1, res[sizeFr:], sig.E[:sizeFr])
	return res[:]
}

// SetBytes sets sig from a buffer in binary.
// buf is read interpreted as r||s
// It returns the number of bytes read from buf.
func (sig *SchnorrSignature) SetBytes(buf []byte) (int, error) {
	n := 0
	if len(buf) < sizeSignature {
		return n, io.ErrShortBuffer
	}
	subtle.ConstantTimeCopy(1, sig.S[:], buf[:sizeFr])
	n += sizeFr
	subtle.ConstantTimeCopy(1, sig.E[:], buf[sizeFr:2*sizeFr])
	n += sizeFr
	return n, nil
}

func GenerateSchnorrSigner(r io.Reader) (*SchnorrSigner, error) {
	x, err := secp256k1RandFieldElement(r)
	if err != nil {
		return nil, err
	}
	ss := &SchnorrSigner{}
	x.FillBytes(ss.scalar[:sizeFr])
	_, g := secp256k1.Generators()
	ss.PublicKey.A.ScalarMultiplication(&g, x)
	return ss, nil
}

// Choose a random k in Fp
// r = g^k
// e = H(r||msg)
// s = k - x*e
// return (s, e)
func (ss *SchnorrSigner) Sign(msg []byte, hFunc hash.Hash) ([]byte, error) {
	hFunc.Reset()
	hFunc.Write(msg)
	msgH := hFunc.Sum(nil)
	hFunc.Reset()
	csprng, err := nonce(ss.scalar[:sizeFr], msgH)
	if err != nil {
		return nil, err
	}
	// Am I selecting a random number in the right way?
	k, err := secp256k1RandFieldElement(csprng)
	if err != nil {
		return nil, err
	}
	_, g := secp256k1.Generators()
	r := new(secp256k1.G1Affine).ScalarMultiplication(&g, k).RawBytes()

	hFunc.Reset()
	hFunc.Write(r[:sizeFr])
	hFunc.Write(msg)
	// e = H(r||msg)
	e := new(secp256k1_fr.Element).SetBytes(hFunc.Sum(nil))
	hFunc.Reset()

	x := new(secp256k1_fr.Element).SetBytes(ss.scalar[:sizeFr])
	// s = k - x*e (mod order)
	s := new(secp256k1_fr.Element).Mul(x, e)
	s.Sub(new(secp256k1_fr.Element).SetBigInt(k), s)

	var sig SchnorrSignature
	sig.S = s.Bytes()
	sig.E = e.Bytes()

	return sig.Bytes(), nil
}

// Verify that sig is a valid signature of msg by pk
// r = g^s * A^e
// e' = H(r||msg)
// return e == e'
func (pk *SchnorrPublicKey) Verify(sigB, msg []byte, hFunc hash.Hash) (bool, error) {
	var sig SchnorrSignature
	if _, err := sig.SetBytes(sigB); err != nil {
		return false, err
	}
	s, e := new(big.Int).SetBytes(sig.S[:sizeFr]), new(big.Int).SetBytes(sig.E[:sizeFr])
	_, g := secp256k1.Generators()

	rv := new(secp256k1.G1Affine).ScalarMultiplication(&g, s)
	rv.Add(rv, new(secp256k1.G1Affine).ScalarMultiplication(&pk.A, e))

	rvB := rv.RawBytes()
	hFunc.Reset()
	hFunc.Write(rvB[:sizeFr])
	hFunc.Write(msg)
	ev := hFunc.Sum(nil)
	hFunc.Reset()
	return bytes.Equal(sig.E[:sizeFr], ev[:sizeFr]), nil
}
