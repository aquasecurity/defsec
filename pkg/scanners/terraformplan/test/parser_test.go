package terraformplan

import (
	"github.com/aquasecurity/defsec/pkg/scanners/terraformplan/parser"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_Parse_Plan_File(t *testing.T) {

	planFile, err := parser.New().ParseFile("testdata/plan.json")
	require.NoError(t, err)

	assert.NotNil(t, planFile)
	fs, err := planFile.ToFS()
	require.NoError(t, err)

	assert.NotNil(t, fs)
}

func Test_Parse_Plan_File_Include_Map_Slice(t *testing.T) {

	planFile, err := parser.New().ParseFile("testdata/plan_include_map_slice.json")
	require.NoError(t, err)

	assert.NotNil(t, planFile)
	fs, err := planFile.ToFS()
	require.NoError(t, err)

	assert.NotNil(t, fs)

	file, err := fs.ReadFile("main.tf")
	_, diags := hclsyntax.ParseTemplate(file, "main.tf", hcl.Pos{Line: 1, Column: 1})
	assert.False(t, diags.HasErrors())
}
