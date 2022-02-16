package sam

import (
	"github.com/aquasecurity/defsec/provider/aws/sam"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
	"github.com/aquasecurity/trivy-config-parsers/types"
)

func getFunctions(cfFile parser.FileContext) (functions []sam.Function) {

	functionResources := cfFile.GetResourceByType("AWS::Serverless::Function")
	for _, r := range functionResources {
		function := sam.Function{
			Metadata:     r.Metadata(),
			FunctionName: r.GetStringProperty("FunctionName"),
			Tracing:      r.GetStringProperty("Tracing", sam.TracingModePassThrough),
		}

		setFunctionPolicies(r, &function)
		functions = append(functions, function)
	}

	return functions
}

func setFunctionPolicies(r *parser.Resource, function *sam.Function) {
	policies := r.GetProperty("Policies")
	if policies.IsNotNil() {
		if policies.IsString() {
			function.ManagedPolicies = append(function.ManagedPolicies, policies.AsStringValue())
		} else if policies.IsList() {
			for _, property := range policies.AsList() {
				if property.IsMap() {
					function.Policies = append(function.Policies, types.String(property.GetJsonBytesAsString(), property.Metadata()))
				} else {
					function.ManagedPolicies = append(function.ManagedPolicies, property.AsStringValue())
				}

			}
		}
	}
}
