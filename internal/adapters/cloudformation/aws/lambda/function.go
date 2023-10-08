package lambda

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/lambda"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getFunctions(ctx parser.FileContext) (functions []lambda.Function) {

	functionResources := ctx.GetResourcesByType("AWS::Lambda::Function")

	for _, r := range functionResources {

		function := lambda.Function{
			Metadata: r.Metadata(),
			Tracing: lambda.Tracing{
				Metadata: r.Metadata(),
				Mode:     types.StringDefault("PassThrough", r.Metadata()),
			},
			VpcConfig: lambda.VpcConfig{
				Metadata: r.Metadata(),
				VpcId:    types.StringDefault("", r.Metadata()),
			},

			Permissions: getPermissions(r, ctx),
		}

		if prop := r.GetProperty("TracingConfig"); prop.IsNotNil() {
			function.Tracing = lambda.Tracing{
				Metadata: prop.Metadata(),
				Mode:     prop.GetStringProperty("Mode", "PassThrough"),
			}
		}

		if vpcProp := r.GetProperty("VpcConfig"); vpcProp.IsNotNil() {
			function.VpcConfig = lambda.VpcConfig{
				Metadata: vpcProp.Metadata(),
				VpcId:    vpcProp.GetStringProperty("VpcId", ""),
			}
		}

		functions = append(functions, function)
	}

	return functions
}

func getPermissions(funcR *parser.Resource, ctx parser.FileContext) (perms []lambda.Permission) {

	permissionResources := ctx.GetResourcesByType("AWS::Lambda::Permission")

	for _, r := range permissionResources {
		if prop := r.GetStringProperty("FunctionName"); prop.EqualTo(funcR.ID()) {
			perm := lambda.Permission{
				Metadata:  r.Metadata(),
				Principal: r.GetStringProperty("Principal"),
				SourceARN: r.GetStringProperty("SourceArn"),
			}
			perms = append(perms, perm)
		}
	}

	return perms
}
