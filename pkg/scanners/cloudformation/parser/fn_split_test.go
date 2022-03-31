package parser

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/cftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"testing"
)

/*
	Fn::Split: ["::", "s3::bucket::to::split"]

*/

func Test_resolve_split_value(t *testing.T) {

	property := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Split": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "::",
								},
							},
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "s3::bucket::to::split",
								},
							},
						},
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(property)
	require.True(t, success)
	assert.True(t, resolvedProperty.IsNotNil())
	assert.True(t, resolvedProperty.IsList())
	listContents := resolvedProperty.AsList()
	assert.Len(t, listContents, 4)

}
