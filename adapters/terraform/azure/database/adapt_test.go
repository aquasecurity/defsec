package database

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/azure/database"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  database.Database
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: database.Database{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptPostgreSQLConfig(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  database.PostgresSQLConfig
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: database.PostgresSQLConfig{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptPostgreSQLConfig(modules.GetBlocks()[0], nil)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptMSSQLSecurityAlertPolicy(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  database.SecurityAlertPolicy
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: database.SecurityAlertPolicy{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptMSSQLSecurityAlertPolicy(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptFirewallRule(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  database.FirewallRule
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: database.FirewallRule{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptFirewallRule(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptMSSQLExtendedAuditingPolicy(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  database.ExtendedAuditingPolicy
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: database.ExtendedAuditingPolicy{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptMSSQLExtendedAuditingPolicy(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
