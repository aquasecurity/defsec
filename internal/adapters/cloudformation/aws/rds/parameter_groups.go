package rds

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getParameterGroups(ctx parser.FileContext) (parametergroups []rds.ParameterGroups) {

	for _, r := range ctx.GetResourcesByType("AWS::RDS::DBParameterGroup") {

		paramgroup := rds.ParameterGroups{
			Metadata:               r.Metadata(),
			DBParameterGroupName:   r.GetStringProperty("DBParameterGroupName"),
			DBParameterGroupFamily: r.GetStringProperty("DBParameterGroupFamily"),
			Parameters:             getParameters(r),
		}

		parametergroups = append(parametergroups, paramgroup)
	}

	return parametergroups
}

func getParameters(r *parser.Resource) (parameters []rds.Parameters) {

	DBParam := r.GetProperty("Parameters")

	if DBParam.IsNil() || DBParam.IsNotNil() {
		return parameters
	}

	for _, DBP := range DBParam.AsList() {
		parameters = append(parameters, rds.Parameters{
			Metadata:       DBP.Metadata(),
			ParameterName:  types.StringDefault("", DBP.Metadata()),
			ParameterValue: types.StringDefault("", DBP.Metadata()),
		})
	}
	return parameters
}
