package appservice

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/azure/appservice"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptService(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  appservice.Service
	}{
		{
			name: "configured",
			terraform: `
			resource "azurerm_app_service" "my_example" {
				name                = "example-app-service"
				client_cert_enabled = true
			  
				identity {
				  type = "UserAssigned"
				  identity_ids = "webapp1"
				}
				site_config {
					http2_enabled = true
					min_tls_version = "1.0"

				}
				auth_settings {
					enabled = true
				  }
			}
`,
			expected: appservice.Service{
				Metadata:         types2.NewTestMetadata(),
				EnableClientCert: types2.Bool(true, types2.NewTestMetadata()),
				Identity: struct{ Type types2.StringValue }{
					Type: types2.String("UserAssigned", types2.NewTestMetadata()),
				},
				Authentication: struct{ Enabled types2.BoolValue }{
					Enabled: types2.Bool(true, types2.NewTestMetadata()),
				},
				Site: struct {
					EnableHTTP2       types2.BoolValue
					MinimumTLSVersion types2.StringValue
				}{
					EnableHTTP2:       types2.Bool(true, types2.NewTestMetadata()),
					MinimumTLSVersion: types2.String("1.0", types2.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_app_service" "my_example" {
			}
`,
			expected: appservice.Service{
				Metadata:         types2.NewTestMetadata(),
				EnableClientCert: types2.Bool(false, types2.NewTestMetadata()),
				Identity: struct{ Type types2.StringValue }{
					Type: types2.String("", types2.NewTestMetadata()),
				},
				Authentication: struct{ Enabled types2.BoolValue }{
					Enabled: types2.Bool(false, types2.NewTestMetadata()),
				},
				Site: struct {
					EnableHTTP2       types2.BoolValue
					MinimumTLSVersion types2.StringValue
				}{
					EnableHTTP2:       types2.Bool(false, types2.NewTestMetadata()),
					MinimumTLSVersion: types2.String("1.2", types2.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptService(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptFunctionApp(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  appservice.FunctionApp
	}{
		{
			name: "configured",
			terraform: `
			resource "azurerm_function_app" "my_example" {
				name                       = "test-azure-functions"
				https_only                 = true
			}
`,
			expected: appservice.FunctionApp{
				Metadata:  types2.NewTestMetadata(),
				HTTPSOnly: types2.Bool(true, types2.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_function_app" "my_example" {		
			}
`,
			expected: appservice.FunctionApp{
				Metadata:  types2.NewTestMetadata(),
				HTTPSOnly: types2.Bool(false, types2.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptFunctionApp(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_app_service" "my_example" {
		name                = "example-app-service"
		client_cert_enabled = true
	  
		identity {
		  type = "UserAssigned"
		  identity_ids = "webapp1"
		}
		site_config {
			http2_enabled = true
			min_tls_version = "1.0"
		}
		auth_settings {
			enabled = true
		  }
	}
	
	resource "azurerm_function_app" "my_example" {
		name                       = "test-azure-functions"
		https_only                 = true
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Services, 1)
	require.Len(t, adapted.FunctionApps, 1)

	service := adapted.Services[0]
	functionApp := adapted.FunctionApps[0]

	assert.Equal(t, 4, service.EnableClientCert.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, service.EnableClientCert.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, service.Identity.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, service.Identity.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, service.Site.EnableHTTP2.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, service.Site.EnableHTTP2.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, service.Site.MinimumTLSVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, service.Site.MinimumTLSVersion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, service.Authentication.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, service.Authentication.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, functionApp.HTTPSOnly.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, functionApp.HTTPSOnly.GetMetadata().Range().GetEndLine())
}
