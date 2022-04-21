package terraformplan

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/terraformplan/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Parse_Plan_File(t *testing.T) {

	planFile, err := parser.New().ParseFile("testdata/plan.json")
	require.NoError(t, err)

	assert.NotNil(t, planFile)
	fs, err := planFile.ToFS()
	require.NoError(t, err)

	assert.NotNil(t, fs)
}
