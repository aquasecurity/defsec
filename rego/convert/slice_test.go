package convert

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_SliceConversion(t *testing.T) {
	input := []struct {
		X string
		Y int
		Z struct {
			A float64
		}
	}{
		{},
	}
	input[0].Z.A = 123
	converted := SliceToRego(reflect.ValueOf(input))
	assert.Equal(t, []interface{}{map[string]interface{}{"z": map[string]interface{}{}}}, converted)
}
