package wts

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHW(t *testing.T) {
	assert.Equal(t, HamWeight(5), 2)
	assert.Equal(t, HamWeight(7), 3)
	assert.Equal(t, HamWeight(8), 1)
	assert.Equal(t, HamWeight(15), 4)
}

func TestBinPos(t *testing.T) {
	fmt.Println(5, BinPos(5))
	fmt.Println(5, BinPos(7))
	fmt.Println(5, BinPos(8))
	fmt.Println(5, BinPos(15))
}
