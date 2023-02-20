package cognito

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cognito"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getPool(ctx parser.FileContext) []cognito.UserPool {

	var pools []cognito.UserPool

	resources := ctx.GetResourcesByType("AWS::Cognito::UserPool")

	for _, r := range resources {
		pools = append(pools, cognito.UserPool{
			Metadata:         r.Metadata(),
			Id:               types.String("", r.Metadata()),
			MfaConfiguration: r.GetStringProperty("MfaConfiguration"),
		})
	}

	return pools
}
