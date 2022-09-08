package armjson

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/stretchr/testify/require"
)

func Test_Null(t *testing.T) {
	example := []byte(`null`)
	var output string
	ref := &output
	err := Unmarshal(example, &ref, types.NewTestMetadata())
	require.NoError(t, err)
}
