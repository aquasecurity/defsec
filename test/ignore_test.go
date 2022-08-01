package test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/providers"

	"github.com/stretchr/testify/assert"
)

var exampleRule = scan.Rule{
	Provider:  providers.AWSProvider,
	Service:   "service",
	ShortCode: "abc123",
	Aliases:   []string{"aws-other-abc123"},
	Severity:  severity.High,
	CustomChecks: scan.CustomChecks{
		Terraform: &scan.TerraformCustomCheck{
			RequiredLabels: []string{"bad"},
			Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results scan.Results) {
				attr := resourceBlock.GetAttribute("secure")
				if attr.IsNil() {
					results.Add("example problem", resourceBlock)
				}
				if attr.IsFalse() {
					results.Add("example problem", attr)
				}
				return
			},
		},
	},
}

func Test_IgnoreAll(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
resource "bad" "my-rule" {
    secure = false // tfsec:ignore:*
}
`)
	assert.Len(t, results.GetFailed(), 0)

}

func Test_IgnoreLineAboveTheBlock(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
// tfsec:ignore:*
resource "bad" "my-rule" {
   secure = false 
}
`)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineAboveTheBlockMatchingParamBool(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
// tfsec:ignore:*[secure=false]
resource "bad" "my-rule" {
   secure = false
}
`)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineAboveTheBlockNotMatchingParamBool(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
// tfsec:ignore:*[secure=true]
resource "bad" "my-rule" {
   secure = false 
}
`)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreLineAboveTheBlockMatchingParamString(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
// tfsec:ignore:*[name=myrule]
resource "bad" "my-rule" {
    name = "myrule"
    secure = false
}
`)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineAboveTheBlockNotMatchingParamString(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
// tfsec:ignore:*[name=myrule2]
resource "bad" "my-rule" {
    name = "myrule"
    secure = false 
}
`)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreLineAboveTheBlockMatchingParamInt(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
// tfsec:ignore:*[port=123]
resource "bad" "my-rule" {
   secure = false
   port = 123
}
`)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineAboveTheBlockNotMatchingParamInt(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
// tfsec:ignore:*[port=456]
resource "bad" "my-rule" {
   secure = false 
   port = 123
}
`)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreLineStackedAboveTheBlock(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
// tfsec:ignore:*
// tfsec:ignore:a
// tfsec:ignore:b
// tfsec:ignore:c
// tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineStackedAboveTheBlockWithoutMatch(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
#tfsec:ignore:*

#tfsec:ignore:x
#tfsec:ignore:a
#tfsec:ignore:b
#tfsec:ignore:c
#tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreLineStackedAboveTheBlockWithHashesWithoutSpaces(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
#tfsec:ignore:*
#tfsec:ignore:a
#tfsec:ignore:b
#tfsec:ignore:c
#tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineStackedAboveTheBlockWithoutSpaces(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
//tfsec:ignore:*
//tfsec:ignore:a
//tfsec:ignore:b
//tfsec:ignore:c
//tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineAboveTheLine(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)
	results := scanHCL(t, `
resource "bad" "my-rule" {
	# tfsec:ignore:aws-service-abc123
    secure = false
}
`)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreWithExpDateIfDateBreachedThenDontIgnore(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:aws-service-abc123:exp:2000-01-02
}
`)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreWithExpDateIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:aws-service-abc123:exp:2221-01-02
}
`)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreWithExpDateIfDateInvalidThenDropTheIgnore(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
resource "bad" "my-rule" {
   secure = false # tfsec:ignore:aws-service-abc123:exp:2221-13-02
}
`)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreAboveResourceBlockWithExpDateIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
#tfsec:ignore:aws-service-abc123:exp:2221-01-02
resource "bad" "my-rule" {
}
`)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreAboveResourceBlockWithExpDateAndMultipleIgnoresIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, `
# tfsec:ignore:aws-service-abc123:exp:2221-01-02
resource "bad" "my-rule" {
	
}
`)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreIgnoreWithExpiryAndWorkspaceAndWorkspaceSupplied(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCLWithWorkspace(t, `
# tfsec:ignore:aws-service-abc123:exp:2221-01-02:ws:testworkspace
resource "bad" "my-rule" {
}
`, "testworkspace")
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreInline(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, fmt.Sprintf(`
	resource "bad" "sample" {
		  secure = false # tfsec:ignore:%s
	}
	  `, exampleRule.LongID()))
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreIgnoreWithExpiryAndWorkspaceButWrongWorkspaceSupplied(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCLWithWorkspace(t, `
# tfsec:ignore:aws-service-abc123:exp:2221-01-02:ws:otherworkspace
resource "bad" "my-rule" {
	
}
`, "testworkspace")
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreWithAliasCodeStillIgnored(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCLWithWorkspace(t, `
# tfsec:ignore:aws-other-abc123
resource "bad" "my-rule" {
	
}
`, "testworkspace")
	assert.Len(t, results.GetFailed(), 0)
}
