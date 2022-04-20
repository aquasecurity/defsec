package parser

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Parse_Plan_File(t *testing.T) {

	planFile, err := New().ParseFile("/tmp/plan.json")
	require.NoError(t, err)

	assert.NotNil(t, planFile)
	fs, err := planFile.ToFS()
	require.NoError(t, err)

	assert.NotNil(t, fs)

	contents, err := fs.ReadFile("main.tf")
	require.NoError(t, err)

	fmt.Println(string(contents))
}
