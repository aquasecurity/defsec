package test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/stretchr/testify/assert"
)

var exampleTrivyRule = scan.Rule{
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

func Test_TrivyIgnoreAll(t *testing.T) {

	var testCases = []struct {
		name         string
		inputOptions string
		assertLength int
	}{
		{name: "TrivyIgnoreAll", inputOptions: `
resource "bad" "my-rule" {
    secure = false // trivy:ignore:*
}
`, assertLength: 0},
		{name: "TrivyIgnoreLineAboveTheBlock", inputOptions: `
// trivy:ignore:*
resource "bad" "my-rule" {
   secure = false 
}
`, assertLength: 0},
		{name: "TrivyIgnoreLineAboveTheBlockMatchingParamBool", inputOptions: `
// trivy:ignore:*[secure=false]
resource "bad" "my-rule" {
   secure = false
}
`, assertLength: 0},
		{name: "TrivyIgnoreLineAboveTheBlockNotMatchingParamBool", inputOptions: `
// trivy:ignore:*[secure=true]
resource "bad" "my-rule" {
   secure = false 
}
`, assertLength: 1},
		{name: "TrivyIgnoreLineAboveTheBlockMatchingParamString", inputOptions: `
// trivy:ignore:*[name=myrule]
resource "bad" "my-rule" {
    name = "myrule"
    secure = false
}
`, assertLength: 0},
		{name: "TrivyIgnoreLineAboveTheBlockNotMatchingParamString", inputOptions: `
// trivy:ignore:*[name=myrule2]
resource "bad" "my-rule" {
    name = "myrule"
    secure = false 
}
`, assertLength: 1},
		{name: "TrivyIgnoreLineAboveTheBlockMatchingParamInt", inputOptions: `
// trivy:ignore:*[port=123]
resource "bad" "my-rule" {
   secure = false
   port = 123
}
`, assertLength: 0},
		{name: "TrivyIgnoreLineAboveTheBlockNotMatchingParamInt", inputOptions: `
// trivy:ignore:*[port=456]
resource "bad" "my-rule" {
   secure = false 
   port = 123
}
`, assertLength: 1},
		{name: "TrivyIgnoreLineStackedAboveTheBlock", inputOptions: `
// trivy:ignore:*
// trivy:ignore:a
// trivy:ignore:b
// trivy:ignore:c
// trivy:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`, assertLength: 0},
		{name: "TrivyIgnoreLineStackedAboveTheBlockWithoutMatch", inputOptions: `
#trivy:ignore:*

#trivy:ignore:x
#trivy:ignore:a
#trivy:ignore:b
#trivy:ignore:c
#trivy:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`, assertLength: 1},
		{name: "TrivyIgnoreLineStackedAboveTheBlockWithHashesWithoutSpaces", inputOptions: `
#trivy:ignore:*
#trivy:ignore:a
#trivy:ignore:b
#trivy:ignore:c
#trivy:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`, assertLength: 0},
		{name: "TrivyIgnoreLineStackedAboveTheBlockWithoutSpaces", inputOptions: `
//trivy:ignore:*
//trivy:ignore:a
//trivy:ignore:b
//trivy:ignore:c
//trivy:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`, assertLength: 0},
		{name: "TrivyIgnoreLineAboveTheLine", inputOptions: `
resource "bad" "my-rule" {
	# trivy:ignore:aws-service-abc123
    secure = false
}
`, assertLength: 0},
		{name: "TrivyIgnoreWithExpDateIfDateBreachedThenDontIgnore", inputOptions: `
resource "bad" "my-rule" {
    secure = false # trivy:ignore:aws-service-abc123:exp:2000-01-02
}
`, assertLength: 1},
		{name: "TrivyIgnoreWithExpDateIfDateNotBreachedThenIgnoreIgnore", inputOptions: `
resource "bad" "my-rule" {
    secure = false # trivy:ignore:aws-service-abc123:exp:2221-01-02
}
`, assertLength: 0},
		{name: "TrivyIgnoreWithExpDateIfDateInvalidThenDropTheIgnore", inputOptions: `
resource "bad" "my-rule" {
   secure = false # trivy:ignore:aws-service-abc123:exp:2221-13-02
}
`, assertLength: 1},
		{name: "TrivyIgnoreAboveResourceBlockWithExpDateIfDateNotBreachedThenIgnoreIgnore", inputOptions: `
#trivy:ignore:aws-service-abc123:exp:2221-01-02
resource "bad" "my-rule" {
}
`, assertLength: 0},
		{name: "TrivyIgnoreAboveResourceBlockWithExpDateAndMultipleIgnoresIfDateNotBreachedThenIgnoreIgnore", inputOptions: `
# trivy:ignore:aws-service-abc123:exp:2221-01-02
resource "bad" "my-rule" {
	
}
`, assertLength: 0},
		{name: "TrivyIgnoreForImpliedIAMResource", inputOptions: `
terraform {
required_version = "~> 1.1.6"

required_providers {
aws = {
source  = "hashicorp/aws"
version = "~> 3.48"
}
}
}

# Retrieve an IAM group defined outside of this Terraform config.

# trivy:ignore:aws-iam-enforce-mfa
data "aws_iam_group" "externally_defined_group" {
group_name = "group-name" # trivy:ignore:aws-iam-enforce-mfa
}

# Create an IAM policy and attach it to the group.

# trivy:ignore:aws-iam-enforce-mfa
resource "aws_iam_policy" "test_policy" {
name   = "test-policy" # trivy:ignore:aws-iam-enforce-mfa
policy = data.aws_iam_policy_document.test_policy.json # trivy:ignore:aws-iam-enforce-mfa
}

# trivy:ignore:aws-iam-enforce-mfa
resource "aws_iam_group_policy_attachment" "test_policy_attachment" {
group      = data.aws_iam_group.externally_defined_group.group_name # trivy:ignore:aws-iam-enforce-mfa
policy_arn = aws_iam_policy.test_policy.arn # trivy:ignore:aws-iam-enforce-mfa
}

# trivy:ignore:aws-iam-enforce-mfa
data "aws_iam_policy_document" "test_policy" {
statement {
sid = "PublishToCloudWatch" # trivy:ignore:aws-iam-enforce-mfa
actions = [
"cloudwatch:PutMetricData", # trivy:ignore:aws-iam-enforce-mfa
]
resources = ["*"] # trivy:ignore:aws-iam-enforce-mfa
}
}
`, assertLength: 0}}

	reg := rules.Register(exampleTrivyRule, nil)
	defer rules.Deregister(reg)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := scanHCL(t, tc.inputOptions)
			assert.Len(t, results.GetFailed(), tc.assertLength)
		})
	}
}

func Test_TrivyIgnoreIgnoreWithExpiryAndWorkspaceAndWorkspaceSupplied(t *testing.T) {
	reg := rules.Register(exampleTrivyRule, nil)
	defer rules.Deregister(reg)

	results := scanHCLWithWorkspace(t, `
# trivy:ignore:aws-service-abc123:exp:2221-01-02:ws:testworkspace
resource "bad" "my-rule" {
}
`, "testworkspace")
	assert.Len(t, results.GetFailed(), 0)
}

func Test_TrivyIgnoreIgnoreWithExpiryAndWorkspaceButWrongWorkspaceSupplied(t *testing.T) {
	reg := rules.Register(exampleTrivyRule, nil)
	defer rules.Deregister(reg)

	results := scanHCLWithWorkspace(t, `
# trivy:ignore:aws-service-abc123:exp:2221-01-02:ws:otherworkspace
resource "bad" "my-rule" {
	
}
`, "testworkspace")
	assert.Len(t, results.GetFailed(), 1)
}

func Test_TrivyIgnoreWithAliasCodeStillIgnored(t *testing.T) {
	reg := rules.Register(exampleTrivyRule, nil)
	defer rules.Deregister(reg)

	results := scanHCLWithWorkspace(t, `
# trivy:ignore:aws-other-abc123
resource "bad" "my-rule" {
	
}
`, "testworkspace")
	assert.Len(t, results.GetFailed(), 0)
}

func Test_TrivyIgnoreInline(t *testing.T) {
	reg := rules.Register(exampleRule, nil)
	defer rules.Deregister(reg)

	results := scanHCL(t, fmt.Sprintf(`
	resource "bad" "sample" {
		  secure = false # trivy:ignore:%s
	}
	  `, exampleRule.LongID()))
	assert.Len(t, results.GetFailed(), 0)
}
