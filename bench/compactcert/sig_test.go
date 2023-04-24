package compactcert

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSchnorrSign(t *testing.T) {
	signer, err := GenerateSchnorrSigner(rand.Reader)
	require.NoError(t, err)
	msg := []byte("hello world")
	hFunc := sha256.New()
	sig, err := signer.Sign(msg, hFunc)
	require.NoError(t, err)
	ok, err := signer.Verify(sig, msg, hFunc)
	require.NoError(t, err)
	require.True(t, ok)
}
