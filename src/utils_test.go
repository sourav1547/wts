package wts

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHW(t *testing.T) {
	assert.Equal(t, ham_weight(5), 2)
	assert.Equal(t, ham_weight(7), 3)
	assert.Equal(t, ham_weight(8), 1)
	assert.Equal(t, ham_weight(15), 4)
}

func TestBinPos(t *testing.T) {
	fmt.Println(5, bin_pos(5))
	fmt.Println(5, bin_pos(7))
	fmt.Println(5, bin_pos(8))
	fmt.Println(5, bin_pos(15))
}
