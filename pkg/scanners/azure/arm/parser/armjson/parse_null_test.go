package armjson

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Null(t *testing.T) {
	example := []byte(`null`)
	var output string
	ref := &output
	err := Unmarshal(example, &ref)
	require.NoError(t, err)
}
