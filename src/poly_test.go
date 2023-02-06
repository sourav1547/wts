package wts

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poly "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
)

func TestPolynomialEval(t *testing.T) {

	// build polynomial
	f := make(poly.Polynomial, 20)
	for i := 0; i < 20; i++ {
		f[i].SetOne()
	}

	// random value
	var point fr.Element
	point.SetRandom()

	// compute manually f(val)
	var expectedEval, one, den fr.Element
	var expo big.Int
	one.SetOne()
	expo.SetUint64(20)
	expectedEval.Exp(point, &expo).
		Sub(&expectedEval, &one)
	den.Sub(&point, &one)
	expectedEval.Div(&expectedEval, &den)

	// compute purported evaluation
	purportedEval := f.Eval(&point)

	// check
	if !purportedEval.Equal(&expectedEval) {
		t.Fatal("polynomial evaluation failed")
	}
}

func TestPolynomialAddConstantInPlace(t *testing.T) {

	// build polynomial
	f := make(poly.Polynomial, 20)
	for i := 0; i < 20; i++ {
		f[i].SetOne()
	}

	// constant to add
	var c fr.Element
	c.SetRandom()

	// add constant
	f.AddConstantInPlace(&c)

	// check
	var expectedCoeffs, one fr.Element
	one.SetOne()
	expectedCoeffs.Add(&one, &c)
	for i := 0; i < 20; i++ {
		if !f[i].Equal(&expectedCoeffs) {
			t.Fatal("AddConstantInPlace failed")
		}
	}
}

func TestPolynomialSubConstantInPlace(t *testing.T) {

	// build polynomial
	f := make(poly.Polynomial, 20)
	for i := 0; i < 20; i++ {
		f[i].SetOne()
	}

	// constant to sub
	var c fr.Element
	c.SetRandom()

	// sub constant
	f.SubConstantInPlace(&c)

	// check
	var expectedCoeffs, one fr.Element
	one.SetOne()
	expectedCoeffs.Sub(&one, &c)
	for i := 0; i < 20; i++ {
		if !f[i].Equal(&expectedCoeffs) {
			t.Fatal("SubConstantInPlace failed")
		}
	}
}

func TestPolynomialScaleInPlace(t *testing.T) {

	// build polynomial
	f := make(poly.Polynomial, 20)
	for i := 0; i < 20; i++ {
		f[i].SetOne()
	}

	// constant to scale by
	var c fr.Element
	c.SetRandom()

	// scale by constant
	f.ScaleInPlace(&c)

	// check
	for i := 0; i < 20; i++ {
		if !f[i].Equal(&c) {
			t.Fatal("ScaleInPlace failed")
		}
	}

}

func TestPolynomialAdd(t *testing.T) {

	// build unbalanced polynomials
	f1 := make(poly.Polynomial, 20)
	f1Backup := make(poly.Polynomial, 20)
	for i := 0; i < 20; i++ {
		f1[i].SetOne()
		f1Backup[i].SetOne()
	}
	f2 := make(poly.Polynomial, 10)
	f2Backup := make(poly.Polynomial, 10)
	for i := 0; i < 10; i++ {
		f2[i].SetOne()
		f2Backup[i].SetOne()
	}

	// expected result
	var one, two fr.Element
	one.SetOne()
	two.Double(&one)
	expectedSum := make(poly.Polynomial, 20)
	for i := 0; i < 10; i++ {
		expectedSum[i].Set(&two)
	}
	for i := 10; i < 20; i++ {
		expectedSum[i].Set(&one)
	}

	// caller is empty
	var g poly.Polynomial
	g.Add(f1, f2)
	if !g.Equal(expectedSum) {
		t.Fatal("add polynomials fails")
	}
	if !f1.Equal(f1Backup) {
		t.Fatal("side effect, f1 should not have been modified")
	}
	if !f2.Equal(f2Backup) {
		t.Fatal("side effect, f2 should not have been modified")
	}

	// all operands are distincts
	_f1 := f1.Clone()
	_f1.Add(f1, f2)
	if !_f1.Equal(expectedSum) {
		t.Fatal("add polynomials fails")
	}
	if !f1.Equal(f1Backup) {
		t.Fatal("side effect, f1 should not have been modified")
	}
	if !f2.Equal(f2Backup) {
		t.Fatal("side effect, f2 should not have been modified")
	}

	// first operand = caller
	_f1 = f1.Clone()
	_f2 := f2.Clone()
	_f1.Add(_f1, _f2)
	if !_f1.Equal(expectedSum) {
		t.Fatal("add polynomials fails")
	}
	if !_f2.Equal(f2Backup) {
		t.Fatal("side effect, _f2 should not have been modified")
	}

	// second operand = caller
	_f1 = f1.Clone()
	_f2 = f2.Clone()
	_f1.Add(_f2, _f1)
	if !_f1.Equal(expectedSum) {
		t.Fatal("add polynomials fails")
	}
	if !_f2.Equal(f2Backup) {
		t.Fatal("side effect, _f2 should not have been modified")
	}
}
