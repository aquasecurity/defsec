package specs

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadSpecs(t *testing.T) {
	tests := []struct {
		name         string
		specName     string
		wantSpecPath string
	}{
		{name: "validate nsa spec", specName: "nsa", wantSpecPath: "./testdata/nsa-1.0.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantSpecData, err := os.ReadFile(tt.wantSpecPath)
			assert.NoError(t, err)
			gotSpecData := GetSpec("nsa")
			assert.Equal(t, gotSpecData, string(wantSpecData))
		})
	}
}
