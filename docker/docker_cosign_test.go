package docker

import (
	"testing"

	"github.com/containers/image/v5/docker/reference"
	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

func TestCosignReference(t *testing.T) {
	var (
		testDigestEncoded = "20bf21ed457b390829cdbeec8795a7bea1626991fda603e0d01b4e7f60427e55"
		testDigest        = digest.Digest("sha256:" + testDigestEncoded)
		fedora            = "docker.io/library/fedora"
		expected          = fedora + ":sha256-" + testDigestEncoded + ".sig"
	)

	for _, test := range []struct {
		input string
	}{
		{fedora},
		{fedora + ":tag"},
		{fedora + "@sha256:" + testDigestEncoded},
	} {
		ref, err := reference.ParseNamed(test.input)
		require.NoError(t, err, "input: %s", test.input)

		res, err := cosignReference(ref, testDigest)
		require.NoError(t, err, "input: %s", test.input)
		require.NotNil(t, res, "input: %s", test.input)
		require.Equal(t, expected, res.String(), "input: %s", test.input)
	}
}
