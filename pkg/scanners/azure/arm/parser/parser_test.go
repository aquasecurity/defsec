package parser

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/stretchr/testify/assert"

	"github.com/liamg/memoryfs"

	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/pkg/scanners/azure"
)

func TestParser_Parse(t *testing.T) {

	filename := "example.json"

	targetFS := memoryfs.New()

	tests := []struct {
		name           string
		input          string
		want           func() *azure.Deployment
		wantDeployment bool
	}{
		{
			name:           "invalid code",
			input:          `blah`,
			wantDeployment: false,
		},
		{
			name: "basic param",
			input: `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", // another one
  "contentVersion": "1.0.0.0",
  "parameters": {
    "storagePrefix": {
      "type": "string",
      "defaultValue": "x",
      "maxLength": 11,
      "minLength": 3
    }
  },
  "resources": []
}`,
			want: func() *azure.Deployment {
				return &azure.Deployment{
					TargetScope: azure.ScopeResourceGroup,
					Parameters: []azure.Parameter{
						{
							Variable: azure.Variable{
								Name:  "storagePrefix",
								Value: azure.NewValue("x", types.NewTestMetadataWithLines(targetFS, filename, 7, 7, "storagePrefix"), nil),
							},
							Default:    azure.NewValue("x", types.NewTestMetadataWithLines(targetFS, filename, 7, 7, "storagePrefix"), nil),
							Decorators: nil,
						},
					},
				}
			},
			wantDeployment: true,
		},
		{
			name: "storageAccount",
			input: `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", // another one
  "contentVersion": "1.0.0.0",
  "parameters": {},
  "resources": [
{
  "type": "Microsoft.Storage/storageAccounts",
  "apiVersion": "2022-05-01",
  "name": "string",
  "location": "string",
  "tags": {
    "tagName1": "tagValue1",
    "tagName2": "tagValue2"
  },
  "sku": {
    "name": "string"
  },
  "kind": "string",
  "extendedLocation": {
    "name": "string",
    "type": "EdgeZone"
  },
  "identity": {
    "type": "string",
    "userAssignedIdentities": {}
  },
  "properties": {
    "allowSharedKeyAccess":false,
    "customDomain": {
      "name": "string",
      "useSubDomainName":false,
      "number": 123
    },
    "networkAcls": [
		{
			"bypass": "AzureServices1"
		},
		{
			"bypass": "AzureServices2"
		}
	]
  }
}
]
}`,
			want: func() *azure.Deployment {
				return &azure.Deployment{
					TargetScope: azure.ScopeResourceGroup,
					Resources: []azure.Resource{
						{
							Metadata: types.NewTestMetadataWithLines(targetFS, filename, 6, 43, "string"),
							APIVersion: azure.NewValue(
								"2022-05-01",
								types.NewTestMetadataWithLines(targetFS, filename, 8, 8, "apiVersion"),
								nil,
							),
							Type: azure.NewValue(
								"Microsoft.Storage/storageAccounts",
								types.NewTestMetadataWithLines(targetFS, filename, 7, 7, "type"),
								nil,
							),
							Kind:     nil,
							Name:     nil,
							Location: nil,
						},
					},
				}
			},
			wantDeployment: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			require.NoError(t, targetFS.WriteFile(filename, []byte(tt.input), 0644))

			p := New(targetFS, "memoryfs", options.ParserWithDebug(os.Stderr))
			got, err := p.ParseFS(context.Background(), ".")
			require.NoError(t, err)

			if !tt.wantDeployment {
				assert.Len(t, got, 0)
				return
			}

			require.Len(t, got, 1)
			require.Equal(t, tt.want(), got[0])
		})
	}
}
