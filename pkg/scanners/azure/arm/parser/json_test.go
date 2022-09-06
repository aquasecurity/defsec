package parser

import (
	"os"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/azure/arm/parser/armjson"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_JSONUnmarshal(t *testing.T) {
	data, err := os.ReadFile("testdata/example.json")
	require.NoError(t, err)
	var target Template
	require.NoError(t, armjson.Unmarshal(data, &target))
	assert.Equal(t,
		"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
		target.Schema.Raw,
	)
	require.Len(t, target.Schema.Comments, 2)
	assert.Equal(t, " wow this is a comment", target.Schema.Comments[0])
	assert.Equal(t, " another one", target.Schema.Comments[1])

	assert.Equal(t, "1.0.0.0", target.ContentVersion.Raw)
	require.Len(t, target.ContentVersion.Comments, 1)
	assert.Equal(t, " this version is great", target.ContentVersion.Comments[0])

	require.Contains(t, target.Parameters, "storagePrefix")
	prefix := target.Parameters["storagePrefix"]
	/*
	   "type": "string",
	   "defaultValue": "x",
	   "maxLength": 11,
	   "minLength": 3
	*/
	assert.Equal(t, "string", prefix.Type.Raw)
	assert.Equal(t, TypeString, prefix.Type.Type)
	assert.Equal(t, 8, prefix.Type.StartLine)
	assert.Equal(t, 8, prefix.Type.EndLine)

	assert.Equal(t, "x", prefix.DefaultValue.Raw)
	assert.Equal(t, TypeString, prefix.DefaultValue.Type)
	assert.Equal(t, 9, prefix.DefaultValue.StartLine)
	assert.Equal(t, 9, prefix.DefaultValue.EndLine)

	assert.Equal(t, int64(11), prefix.MaxLength.Raw)
	assert.Equal(t, TypeNumber, prefix.MaxLength.Type)
	assert.Equal(t, 10, prefix.MaxLength.StartLine)
	assert.Equal(t, 10, prefix.MaxLength.EndLine)

	assert.Equal(t, int64(3), prefix.MinLength.Raw)
	assert.Equal(t, TypeNumber, prefix.MinLength.Type)
	assert.Equal(t, 11, prefix.MinLength.StartLine)
	assert.Equal(t, 11, prefix.MinLength.EndLine)

}
