package armjson

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_String(t *testing.T) {
	example := []byte(`"hello"`)
	var output string
	err := Unmarshal(example, &output)
	require.NoError(t, err)
	assert.Equal(t, "hello", output)
}

func Test_StringToUninitialisedPointer(t *testing.T) {
	example := []byte(`"hello"`)
	var str *string
	err := Unmarshal(example, str)
	require.Error(t, err)
	assert.Nil(t, str)
}

func Test_String_ToInterface(t *testing.T) {
	example := []byte(`"hello"`)
	var output interface{}
	err := Unmarshal(example, &output)
	require.NoError(t, err)
	assert.Equal(t, "hello", output)
}
