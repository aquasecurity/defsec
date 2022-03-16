package test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/defsec/scanners/terraform/executor"

	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"

	"github.com/aquasecurity/defsec/parsers/terraform"

	"github.com/stretchr/testify/assert"
)

var exampleRule = rules.Rule{
	Provider:  providers.AWSProvider,
	Service:   "service",
	ShortCode: "abc123",
	Severity:  severity.High,
	CustomChecks: rules.CustomChecks{
		Terraform: &rules.TerraformCustomCheck{
			RequiredLabels: []string{"bad"},
			Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
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

	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
    secure = false // tfsec:ignore:*
}
`, t)
	assert.Len(t, results.GetFailed(), 0)

}

func Test_IgnoreLineAboveTheBlock(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
// tfsec:ignore:*
resource "bad" "my-rule" {
   secure = false 
}
`, t)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineAboveTheBlockMatchingParamBool(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
// tfsec:ignore:*[secure=false]
resource "bad" "my-rule" {
   secure = false
}
`, t)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineAboveTheBlockNotMatchingParamBool(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
// tfsec:ignore:*[secure=true]
resource "bad" "my-rule" {
   secure = false 
}
`, t)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreLineAboveTheBlockMatchingParamString(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
// tfsec:ignore:*[name=myrule]
resource "bad" "my-rule" {
    name = "myrule"
    secure = false
}
`, t)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineAboveTheBlockNotMatchingParamString(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
// tfsec:ignore:*[name=myrule2]
resource "bad" "my-rule" {
    name = "myrule"
    secure = false 
}
`, t)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreLineAboveTheBlockMatchingParamInt(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
// tfsec:ignore:*[port=123]
resource "bad" "my-rule" {
   secure = false
   port = 123
}
`, t)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineAboveTheBlockNotMatchingParamInt(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
// tfsec:ignore:*[port=456]
resource "bad" "my-rule" {
   secure = false 
   port = 123
}
`, t)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreLineStackedAboveTheBlock(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
// tfsec:ignore:*
// tfsec:ignore:a
// tfsec:ignore:b
// tfsec:ignore:c
// tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`, t)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineStackedAboveTheBlockWithoutMatch(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
#tfsec:ignore:*

#tfsec:ignore:x
#tfsec:ignore:a
#tfsec:ignore:b
#tfsec:ignore:c
#tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`, t)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreLineStackedAboveTheBlockWithHashesWithoutSpaces(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
#tfsec:ignore:*
#tfsec:ignore:a
#tfsec:ignore:b
#tfsec:ignore:c
#tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`, t)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineStackedAboveTheBlockWithoutSpaces(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
//tfsec:ignore:*
//tfsec:ignore:a
//tfsec:ignore:b
//tfsec:ignore:c
//tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`, t)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreLineAboveTheLine(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)
	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
	# tfsec:ignore:aws-service-abc123
    secure = false
}
`, t)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreWithExpDateIfDateBreachedThenDontIgnore(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:aws-service-abc123:exp:2000-01-02
}
`, t)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreWithExpDateIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:aws-service-abc123:exp:2221-01-02
}
`, t)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreWithExpDateIfDateInvalidThenDropTheIgnore(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
   secure = false # tfsec:ignore:aws-service-abc123:exp:2221-13-02
}
`, t)
	assert.Len(t, results.GetFailed(), 1)
}

func Test_IgnoreAboveResourceBlockWithExpDateIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
#tfsec:ignore:aws-service-abc123:exp:2221-01-02
resource "bad" "my-rule" {
}
`, t)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreAboveResourceBlockWithExpDateAndMultipleIgnoresIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
# tfsec:ignore:aws-service-abc123:exp:2221-01-02
resource "bad" "my-rule" {
	
}
`, t)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreIgnoreWithExpiryAndWorkspaceAndWorkspaceSupplied(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
# tfsec:ignore:aws-service-abc123:exp:2221-01-02:ws:testworkspace
resource "bad" "my-rule" {
}
`, t, executor.OptionWithWorkspaceName("testworkspace"))
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreInline(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(fmt.Sprintf(`
	resource "bad" "sample" {
		  secure = false # tfsec:ignore:%s
	}
	  `, exampleRule.LongID()), t)
	assert.Len(t, results.GetFailed(), 0)
}

func Test_IgnoreIgnoreWithExpiryAndWorkspaceButWrongWorkspaceSupplied(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := testutil.ScanHCL(`
# tfsec:ignore:aws-service-abc123:exp:2221-01-02:ws:otherworkspace
resource "bad" "my-rule" {
	
}
`, t, executor.OptionWithWorkspaceName("testworkspace"))
	assert.Len(t, results.GetFailed(), 1)
}
