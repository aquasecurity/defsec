package armjson

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Boolean_True(t *testing.T) {
	example := []byte(`true`)
	var output bool
	err := Unmarshal(example, &output)
	require.NoError(t, err)
	assert.True(t, output)
}

func Test_Boolean_False(t *testing.T) {
	example := []byte(`false`)
	var output bool
	err := Unmarshal(example, &output)
	require.NoError(t, err)
	assert.False(t, output)
}

func Test_Boolean_ToNonBoolPointer(t *testing.T) {
	example := []byte(`false`)
	var output string
	err := Unmarshal(example, &output)
	require.Error(t, err)
}

func Test_Bool_ToUninitialisedPointer(t *testing.T) {
	example := []byte(`true`)
	var str *string
	err := Unmarshal(example, str)
	require.Error(t, err)
	assert.Nil(t, str)
}

func Test_Bool_ToInterface(t *testing.T) {
	example := []byte(`true`)
	var output interface{}
	err := Unmarshal(example, &output)
	require.NoError(t, err)
	assert.True(t, output.(bool))
}
