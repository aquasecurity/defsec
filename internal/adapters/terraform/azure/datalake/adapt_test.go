package datalake

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/azure/datalake"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptStore(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  datalake.Store
	}{
		{
			name: "enabled",
			terraform: `
			resource "azurerm_data_lake_store" "good_example" {
				encryption_state = "Enabled"
			}
`,
			expected: datalake.Store{
				Metadata:         types2.NewTestMetadata(),
				EnableEncryption: types2.Bool(true, types2.NewTestMetadata()),
			},
		},
		{
			name: "disabled",
			terraform: `
			resource "azurerm_data_lake_store" "good_example" {
				encryption_state = "Disabled"
			}
`,
			expected: datalake.Store{
				Metadata:         types2.NewTestMetadata(),
				EnableEncryption: types2.Bool(false, types2.NewTestMetadata()),
			},
		},
		{
			name: "enabled by default",
			terraform: `
			resource "azurerm_data_lake_store" "good_example" {
			}
`,
			expected: datalake.Store{
				Metadata:         types2.NewTestMetadata(),
				EnableEncryption: types2.Bool(true, types2.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptStore(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_data_lake_store" "good_example" {
		encryption_state = "Disabled"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Stores, 1)
	store := adapted.Stores[0]

	assert.Equal(t, 3, store.EnableEncryption.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, store.EnableEncryption.GetMetadata().Range().GetEndLine())
}
