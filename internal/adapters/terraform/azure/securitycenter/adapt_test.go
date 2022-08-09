package securitycenter

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/azure/securitycenter"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptContact(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  securitycenter.Contact
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_security_center_contact" "example" {
				phone = "+1-555-555-5555"
				alert_notifications = true
			}
`,
			expected: securitycenter.Contact{
				Metadata:                 types2.NewTestMetadata(),
				EnableAlertNotifications: types2.Bool(true, types2.NewTestMetadata()),
				Phone:                    types2.String("+1-555-555-5555", types2.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_security_center_contact" "example" {
			}
`,
			expected: securitycenter.Contact{
				Metadata:                 types2.NewTestMetadata(),
				EnableAlertNotifications: types2.Bool(false, types2.NewTestMetadata()),
				Phone:                    types2.String("", types2.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptContact(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSubscription(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  securitycenter.SubscriptionPricing
	}{
		{
			name: "free tier",
			terraform: `
			resource "azurerm_security_center_subscription_pricing" "example" {
				tier          = "Free"
			}`,
			expected: securitycenter.SubscriptionPricing{
				Metadata: types2.NewTestMetadata(),
				Tier:     types2.String("Free", types2.NewTestMetadata()),
			},
		},
		{
			name: "default - free tier",
			terraform: `
			resource "azurerm_security_center_subscription_pricing" "example" {
			}`,
			expected: securitycenter.SubscriptionPricing{
				Metadata: types2.NewTestMetadata(),
				Tier:     types2.String("Free", types2.NewTestMetadata()),
			},
		},
		{
			name: "standard tier",
			terraform: `
			resource "azurerm_security_center_subscription_pricing" "example" {
				tier          = "Standard"
			}`,
			expected: securitycenter.SubscriptionPricing{
				Metadata: types2.NewTestMetadata(),
				Tier:     types2.String("Standard", types2.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSubscription(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_security_center_contact" "example" {
		phone = "+1-555-555-5555"
		alert_notifications = true
	}

	resource "azurerm_security_center_subscription_pricing" "example" {
		tier          = "Standard"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Contacts, 1)
	require.Len(t, adapted.Subscriptions, 1)

	contact := adapted.Contacts[0]
	sub := adapted.Subscriptions[0]

	assert.Equal(t, 3, contact.Phone.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, contact.Phone.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, contact.EnableAlertNotifications.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, contact.EnableAlertNotifications.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 8, sub.Tier.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, sub.Tier.GetMetadata().Range().GetEndLine())
}
