package rds

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/aws/rds"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  rds.RDS
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: rds.RDS{},
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

func Test_adaptClusterInstance(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  rds.ClusterInstance
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: rds.ClusterInstance{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptClusterInstance(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptClassicDBSecurityGroup(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  rds.DBSecurityGroup
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: rds.DBSecurityGroup{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptClassicDBSecurityGroup(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptInstance(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  rds.Instance
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: rds.Instance{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptInstance(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptCluster(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  rds.Cluster
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: rds.Cluster{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted, _ := adaptCluster(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptPerformanceInsights(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  rds.PerformanceInsights
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: rds.PerformanceInsights{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptPerformanceInsights(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptEncryption(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  rds.Encryption
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: rds.Encryption{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptEncryption(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
