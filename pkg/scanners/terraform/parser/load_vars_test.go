package parser

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/zclconf/go-cty/cty"
)

func Test_JsonVarsFile(t *testing.T) {

	_, tmp, tidy := testutil.CreateFS(t, map[string]string{
		"test.tfvars.json": `
{
	"variable": {
		"foo": {
			"default": "bar"
		},
		"baz": "qux"
	},
	"foo2": true,
	"foo3": 3
}
`,
	})
	defer tidy()

	vars, _ := loadTFVars([]string{filepath.Join(tmp, "test.tfvars.json")})
	assert.Equal(t, "bar", vars["variable"].GetAttr("foo").GetAttr("default").AsString())
	assert.Equal(t, "qux", vars["variable"].GetAttr("baz").AsString())
	assert.Equal(t, true, vars["foo2"].True())
	assert.Equal(t, true, vars["foo3"].Equals(cty.NumberIntVal(3)).True())
}
