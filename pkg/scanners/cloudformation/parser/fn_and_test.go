package parser

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/cftypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_resolve_and_value(t *testing.T) {

	property1 := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Equals": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
						},
					},
				},
			},
		},
	}

	property2 := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Equals": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
						},
					},
				},
			},
		},
	}
	andProperty := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::And": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							property1,
							property2,
						},
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(andProperty)
	require.True(t, success)

	assert.True(t, resolvedProperty.IsTrue())
}

func Test_resolve_and_value_not_the_same(t *testing.T) {

	property1 := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Equals": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "bar",
								},
							},
						},
					},
				},
			},
		},
	}

	property2 := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Equals": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
						},
					},
				},
			},
		},
	}
	andProperty := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1, "", nil),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::And": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							property1,
							property2,
						},
					},
				},
			},
		},
	}

	resolvedProperty, success := ResolveIntrinsicFunc(andProperty)
	require.True(t, success)

	assert.False(t, resolvedProperty.IsTrue())
}
