package iam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/util"
	"github.com/aquasecurity/defsec/provider/aws/iam"
)

func retrieveDocument(prop *parser.Property, resource *parser.Resource) (*iam.PolicyDocument, error) {
	policyDoc := util.GetJsonBytes(prop, resource.SourceFormat())
	return iam.ParsePolicyDocument(policyDoc, prop.Metadata())
}

func getPolicies(ctx parser.FileContext) (policies []iam.Policy) {
	for _, policyResource := range ctx.GetResourceByType("AWS::IAM::Policy") {
		var policy iam.Policy
		policyProp := policyResource.GetProperty("PolicyDocument")
		if doc, err := retrieveDocument(policyProp, policyResource); err == nil {
			policy.Document = *doc
		}
		policies = append(policies, policy)
	}
	return policies
}

func getRolePolicies(ctx parser.FileContext) (policies []iam.RolePolicy) {
	for _, policyResource := range ctx.GetResourceByType("AWS::IAM::RolePolicy") {
		var policy iam.RolePolicy
		policyProp := policyResource.GetProperty("PolicyDocument")
		if doc, err := retrieveDocument(policyProp, policyResource); err == nil {
			policy.Document = *doc
		}
		policies = append(policies, policy)
	}
	return policies
}

func getUserPolicies(ctx parser.FileContext) (policies []iam.UserPolicy) {
	for _, policyResource := range ctx.GetResourceByType("AWS::IAM::UserPolicy") {
		var policy iam.UserPolicy
		policyProp := policyResource.GetProperty("PolicyDocument")
		if doc, err := retrieveDocument(policyProp, policyResource); err == nil {
			policy.Document = *doc
		}
		policies = append(policies, policy)
	}
	return policies

}

func getGroupPolicies(ctx parser.FileContext) (policies []iam.GroupPolicy) {
	for _, policyResource := range ctx.GetResourceByType("AWS::IAM::GroupPolicy") {
		var policy iam.GroupPolicy
		policyProp := policyResource.GetProperty("PolicyDocument")
		if doc, err := retrieveDocument(policyProp, policyResource); err == nil {
			policy.Document = *doc
		}
		policies = append(policies, policy)
	}
	return policies
}
