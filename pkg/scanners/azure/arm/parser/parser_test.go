package parser

import (
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/stretchr/testify/assert"

	"github.com/liamg/memoryfs"

	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/pkg/scanners/azure"
)

func createMetadata(targetFS fs.FS, filename string, start, end int, ref string, parent *types.Metadata) types.Metadata {
	child := types.NewMetadata(types.NewRange(filename, start, end, "", targetFS), types.NewNamedReference(ref))
	if parent != nil {
		child = child.WithParent(*parent)
	}
	return child
}

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

				metadata := createMetadata(targetFS, filename, 0, 0, "", nil)

				return &azure.Deployment{
					Metadata:    metadata,
					TargetScope: azure.ScopeResourceGroup,
					Parameters: []azure.Parameter{
						{
							Variable: azure.Variable{
								Name:  "storagePrefix",
								Value: azure.NewValue("x", createMetadata(targetFS, filename, 7, 7, "storagePrefix", &metadata), nil),
							},
							Default:    azure.NewValue("x", createMetadata(targetFS, filename, 7, 7, "storagePrefix", &metadata), nil),
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
  "name": "myResource",
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

				rootMetadata := createMetadata(targetFS, filename, 0, 0, "", nil)
				resourceMetadata := createMetadata(targetFS, filename, 6, 43, "myResource", &rootMetadata)

				return &azure.Deployment{
					Metadata:    rootMetadata,
					TargetScope: azure.ScopeResourceGroup,
					Resources: []azure.Resource{
						{
							Metadata: resourceMetadata,
							APIVersion: azure.NewValue(
								"2022-05-01",
								createMetadata(targetFS, filename, 8, 8, "myResource.apiVersion", &resourceMetadata),
								nil,
							),
							Type: azure.NewValue(
								"Microsoft.Storage/storageAccounts",
								createMetadata(targetFS, filename, 7, 7, "myResource.type", &resourceMetadata),
								nil,
							),
							Kind: azure.NewValue(
								"string",
								createMetadata(targetFS, filename, 18, 18, "myResource.kind", &resourceMetadata),
								nil,
							),
							Name: azure.NewValue(
								"myResource",
								createMetadata(targetFS, filename, 9, 9, "myResource.name", &resourceMetadata),
								nil,
							),
							Location: azure.NewValue(
								"string",
								createMetadata(targetFS, filename, 10, 10, "myResource.location", &resourceMetadata),
								nil,
							),
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
