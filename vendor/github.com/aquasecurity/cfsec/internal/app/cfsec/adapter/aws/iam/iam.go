package iam

import (
	"reflect"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/iam"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result iam.IAM) {
	defer func() {
		if r := recover(); r != nil {
			metadata := cfFile.Metadata()
			debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.Policies = getPolicies(cfFile)
	result.RolePolicies = getRolePolicies(cfFile)
	result.UserPolicies = getUserPolicies(cfFile)
	result.GroupPolicies = getGroupPolicies(cfFile)
	return result

}
