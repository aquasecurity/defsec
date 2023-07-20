package azure

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/stretchr/testify/assert"
)

func Test_ValueAsInt(t *testing.T) {
	val := NewValue(int64(10), types.NewTestMetadata())
	assert.Equal(t, 10, val.AsInt())
}
