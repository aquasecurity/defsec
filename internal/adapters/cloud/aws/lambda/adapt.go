package lambda

import (
	"strings"

	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/lambda"
	"github.com/aquasecurity/defsec/pkg/state"
	lambdaapi "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/liamg/iamgo"
)

type adapter struct {
	*aws.RootAdapter
	api *lambdaapi.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "lambda"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = lambdaapi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Lambda.Functions, err = a.getFunctions()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getFunctions() ([]lambda.Function, error) {

	a.Tracker().SetServiceLabel(" Discovering functions...")

	// we're currently only pulling back LIVE versions
	input := &lambdaapi.ListFunctionsInput{
		Marker: nil,
	}

	var apiFunctions []types.FunctionConfiguration
	for {
		output, err := a.api.ListFunctions(a.Context(), input)
		if err != nil {
			return nil, err
		}
		apiFunctions = append(apiFunctions, output.Functions...)
		a.Tracker().SetTotalResources(len(apiFunctions))
		if output.NextMarker == nil {
			break
		}
		input.Marker = output.NextMarker
	}

	a.Tracker().SetServiceLabel("Adapting functions...")
	return concurrency.Adapt(apiFunctions, a.RootAdapter, a.adaptFunction), nil
}

func (a *adapter) adaptFunction(function types.FunctionConfiguration) (*lambda.Function, error) {
	metadata := a.CreateMetadataFromARN(*function.FunctionArn)
	var tracingMode string
	if function.TracingConfig != nil {
		tracingMode = string(function.TracingConfig.Mode)
	}

	var functionarn string
	if function.FunctionArn != nil {
		functionarn = *function.FunctionArn
	}

	var funcname string
	if function.FunctionName != nil {
		funcname = *function.FunctionName
	}

	var vpcid string
	if function.VpcConfig != nil && function.VpcConfig.VpcId != nil {
		vpcid = *function.VpcConfig.VpcId
	}

	var variables map[string]string
	if function.Environment != nil && function.Environment.Variables != nil {
		variables = function.Environment.Variables
	}

	var runtime string
	if function.Runtime.Values() != nil {
		runtime = string(function.Runtime)
	}

	val, err := a.getPermissions(function, metadata)
	if err != nil {
		return nil, err
	}

	return &lambda.Function{
		Metadata: metadata,
		Tracing: lambda.Tracing{
			Metadata: metadata,
			Mode:     defsecTypes.String(tracingMode, metadata),
		},
		Permissions:  val,
		FunctionName: defsecTypes.String(funcname, metadata),
		FunctionArn:  defsecTypes.String(functionarn, metadata),
		VpcConfig: lambda.VpcConfig{
			Metadata: metadata,
			VpcId:    defsecTypes.String(vpcid, metadata),
		},
		Runtime: defsecTypes.String(runtime, metadata),
		Envrionment: lambda.Environment{
			Metadata:  metadata,
			Variables: defsecTypes.Map(variables, metadata),
		},
	}, nil
}

func (a *adapter) getPermissions(function types.FunctionConfiguration, metadata defsecTypes.Metadata) ([]lambda.Permission, error) {
	var permissions []lambda.Permission
	if output, err := a.api.GetPolicy(a.Context(), &lambdaapi.GetPolicyInput{
		FunctionName: function.FunctionName,
		Qualifier:    function.Version,
	}); err == nil {
		parsed, err := iamgo.ParseString(*output.Policy)
		if err != nil {
			return nil, err
		}
		statements, _ := parsed.Statements()
		for _, statement := range statements {

			var principal string
			principals, _ := statement.Principals()
			if awsPrincipals, _ := principals.AWS(); len(awsPrincipals) > 0 {
				principal = awsPrincipals[0]
			} else if svcPrincipals, _ := principals.Service(); len(svcPrincipals) > 0 {
				principal = svcPrincipals[0]
			}

			var source string
			conditions, _ := statement.Conditions()
			for _, condition := range conditions {
				operator, _ := condition.Operator()
				key, _ := condition.Key()
				values, _ := condition.Value()
				if len(values) == 0 {
					continue
				}
				switch {
				case strings.EqualFold(operator, "StringEquals") && strings.EqualFold(key, "AWS:SourceAccount"):
					source = values[0]
				case strings.EqualFold(operator, "ArnLike") && strings.EqualFold(key, "AWS:SourceArn"):
					source = values[0]
				}
			}

			permissions = append(permissions, lambda.Permission{
				Metadata:  metadata,
				Principal: defsecTypes.String(principal, metadata),
				SourceARN: defsecTypes.String(source, metadata),
			})
		}
	}
	return permissions, nil
}
