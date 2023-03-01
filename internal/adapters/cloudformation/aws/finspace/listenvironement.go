package finspace

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/finspace"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getListEnvironment(ctx parser.FileContext) (listenvironment []finspace.Environment) {

	listEnvironementResources := ctx.GetResourcesByType("AWS::FinSpace::Environment")

	for _, r := range listEnvironementResources {
		le := finspace.Environment{
			Metadata:       r.Metadata(),
			EnvironmentArn: r.GetStringProperty("EnvironmentArn"),
			KmsKeyId:       r.GetStringProperty("KmsKeyId"),
		}
		listenvironment = append(listenvironment, le)
	}

	return listenvironment
}
