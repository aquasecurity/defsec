package parser

import (
	"testing"

	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/zclconf/go-cty/cty"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TFVarsFile(t *testing.T) {
	t.Run("tfvars file", func(t *testing.T) {
		fs := testutil.CreateFS(t, map[string]string{
			"test.tfvars": `instance_type = "t2.large"`,
		})

		vars, err := loadTFVars(fs, []string{"test.tfvars"})
		require.NoError(t, err)
		assert.Equal(t, "t2.large", vars["instance_type"].AsString())
	})

	t.Run("tfvars json file", func(t *testing.T) {
		fs := testutil.CreateFS(t, map[string]string{
			"test.tfvars.json": `{
  "variable": {
    "foo": {
      "default": "bar"
    },
    "baz": "qux"
  },
  "foo2": true,
  "foo3": 3
}`,
		})

		vars, err := loadTFVars(fs, []string{"test.tfvars.json"})
		require.NoError(t, err)
		assert.Equal(t, "bar", vars["variable"].GetAttr("foo").GetAttr("default").AsString())
		assert.Equal(t, "qux", vars["variable"].GetAttr("baz").AsString())
		assert.Equal(t, true, vars["foo2"].True())
		assert.Equal(t, true, vars["foo3"].Equals(cty.NumberIntVal(3)).True())
	})
}
