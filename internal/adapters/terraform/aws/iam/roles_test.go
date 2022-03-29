package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptRoles(t *testing.T) {
	src := `resource "aws_iam_role_policy" "test_policy" {
 	name = "test_policy"
 	role = aws_iam_role.test_role.id
 
 	policy = data.aws_iam_policy_document.s3_policy.json
 }
 
 resource "aws_iam_role" "test_role" {
 	name = "test_role"
 	assume_role_policy = jsonencode({
 		Version = "2012-10-17"
 		Statement = [
 		{
 			Action = "sts:AssumeRole"
 			Effect = "Allow"
 			Sid    = ""
 			Principal = {
 			Service = "s3.amazonaws.com"
 			}
 		},
 		]
 	})
 }
 
 data "aws_iam_policy_document" "s3_policy" {
   statement {
     principals {
       type        = "AWS"
       identifiers = ["arn:aws:iam::123:root"]
     }
     actions   = ["s3:*"]
     resources = ["*"]
   }
 }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	roles := adaptRoles(modules)
	require.Len(t, roles, 1)
	role := roles[0]

	assert.True(t, role.Name.EqualTo("test_role"))
	assert.Equal(t, role.Name.GetMetadata().Range().GetStartLine(), 9)
	assert.Equal(t, role.Name.GetMetadata().Range().GetEndLine(), 9)

	require.Len(t, role.Policies, 1)
	policy := role.Policies[0]
	assert.Equal(t, 1, policy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, policy.GetMetadata().Range().GetEndLine())
	assert.True(t, policy.Name.EqualTo("test_policy"))
	assert.Equal(t, policy.Name.GetMetadata().Range().GetStartLine(), 2)
	assert.Equal(t, policy.Name.GetMetadata().Range().GetEndLine(), 2)

	doc := policy.Document
	assert.Equal(t, 25, doc.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, doc.GetMetadata().Range().GetEndLine())

	statements, r := doc.Parsed.Statements()
	require.Len(t, statements, 1)
	assert.Equal(t, 26, r.StartLine)
	assert.Equal(t, 33, r.EndLine)

	statement := statements[0]
	assert.Equal(t, 26, statement.Range().StartLine)
	assert.Equal(t, 33, statement.Range().EndLine)

	actions, r := statement.Actions()
	assert.Equal(t, 31, r.StartLine)
	assert.Equal(t, 31, r.EndLine)
	require.Len(t, actions, 1)
	action := actions[0]
	assert.Equal(t, "s3:*", action)

	resources, r := statement.Resources()
	assert.Equal(t, 32, r.StartLine)
	assert.Equal(t, 32, r.EndLine)
	require.Len(t, resources, 1)
	resource := resources[0]
	assert.Equal(t, "*", resource)

	principals, r := statement.Principals()
	assert.Equal(t, 27, r.StartLine)
	assert.Equal(t, 30, r.EndLine)

	aws, r := principals.AWS()
	assert.Equal(t, 27, r.StartLine)
	assert.Equal(t, 30, r.EndLine)
	require.Len(t, aws, 1)
	assert.Equal(t, "arn:aws:iam::123:root", aws[0])

	rerange := doc.MetadataFromIamGo(r).Range()
	assert.Equal(t, 27, rerange.GetStartLine())
	assert.Equal(t, 30, rerange.GetEndLine())
}
