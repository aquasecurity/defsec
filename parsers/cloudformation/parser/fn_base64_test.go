package parser

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/cftypes"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"testing"
)

func Test_resolve_base64_value(t *testing.T) {

	property := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Base64": {
					Inner: PropertyInner{
						Type:  cftypes.String,
						Value: "HelloWorld",
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)

	assert.Equal(t, "SGVsbG9Xb3JsZA==", resolvedProperty.AsString())
}
