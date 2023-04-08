package parser

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/extrafs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func Test_TFVarsFile(t *testing.T) {
	t.Run("tfvars file", func(t *testing.T) {
		absPath, err := getAbsPath("testdata/tfvars/terraform.tfvars")
		require.NoError(t, err)

		vars, err := loadTFVars(extrafs.OSDir("/"), []string{absPath})
		require.NoError(t, err)
		assert.Equal(t, "t2.large", vars["instance_type"].AsString())
	})

	t.Run("tfvars json file", func(t *testing.T) {
		absPath, err := getAbsPath("testdata/tfvars/terraform.tfvars.json")
		require.NoError(t, err)

		vars, err := loadTFVars(extrafs.OSDir("/"), []string{absPath})
		require.NoError(t, err)
		assert.Equal(t, "bar", vars["variable"].GetAttr("foo").GetAttr("default").AsString())
		assert.Equal(t, "qux", vars["variable"].GetAttr("baz").AsString())
		assert.Equal(t, true, vars["foo2"].True())
		assert.Equal(t, true, vars["foo3"].Equals(cty.NumberIntVal(3)).True())
	})
}
