//go:build docker
// +build docker

package lambda

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/lambda"

	"github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws/test"
	"github.com/aquasecurity/defsec/pkg/state"
	lambdaapi "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type functionDetails struct {
	name        string
	permissions []permissionDetails
	tracing     string
}

type permissionDetails struct {
	action    string
	principal string
	source    string
}

func Test_Lambda(t *testing.T) {

	tests := []struct {
		name    string
		details functionDetails
	}{
		{
			name: "defaults",
			details: functionDetails{
				name: "myfunction",
			},
		},
		{
			name: "pass-through tracing",
			details: functionDetails{
				name:    "myfunction",
				tracing: "PassThrough",
			},
		},
		{
			name: "active tracing",
			details: functionDetails{
				name:    "myfunction",
				tracing: "Active",
			},
		},
		{
			name: "with permissions",
			details: functionDetails{
				name:    "myfunction",
				tracing: "Active",
				permissions: []permissionDetails{
					{
						action:    "lambda:InvokeFunction",
						principal: "1234567890",
						source:    "*",
					},
				},
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			funcARN := bootstrapFunction(t, ra, tt.details)
			defer removeFunction(t, ra, funcARN)

			testState := &state.State{}
			lambdaAdapter := &adapter{}
			err = lambdaAdapter.Adapt(ra, testState)
			require.NoError(t, err)

			require.Len(t, testState.AWS.Lambda.Functions, 1)
			got := testState.AWS.Lambda.Functions[0]

			if tt.details.tracing == "" {
				tt.details.tracing = lambda.TracingModePassThrough
			}
			assert.Equal(t, tt.details.tracing, got.Tracing.Mode.Value())

			assert.Equal(t, len(tt.details.permissions), len(got.Permissions))

			for _, expectedPermission := range tt.details.permissions {
				var found bool
				for _, actualPermission := range got.Permissions {
					if actualPermission.Principal.Value() == expectedPermission.principal && actualPermission.SourceARN.Value() == expectedPermission.source {
						found = true
						break
					}
				}
				assert.True(t, found)
			}
		})
	}
}

func bootstrapFunction(t *testing.T, ra *aws.RootAdapter, spec functionDetails) string {

	api := lambdaapi.NewFromConfig(ra.SessionConfig())

	output, err := api.CreateFunction(ra.Context(), &lambdaapi.CreateFunctionInput{
		Code: &types.FunctionCode{
			ZipFile: []byte{80, 75, 05, 06, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00},
		},
		FunctionName: &spec.name,
		Role:         &spec.name,
		TracingConfig: &types.TracingConfig{
			Mode: types.TracingMode(spec.tracing),
		},
	})
	require.NoError(t, err)

	for i, permission := range spec.permissions {
		statementID := fmt.Sprintf("%d", i)
		_, err = api.AddPermission(ra.Context(), &lambdaapi.AddPermissionInput{
			Action:       &permission.action,
			FunctionName: &spec.name,
			Qualifier:    output.Version,
			Principal:    &permission.principal,
			StatementId:  &statementID,
			SourceArn:    &permission.source,
		})
		require.NoError(t, err)
	}

	return *output.FunctionArn
}

func removeFunction(t *testing.T, ra *aws.RootAdapter, arn string) {
	api := lambdaapi.NewFromConfig(ra.SessionConfig())
	_, err := api.DeleteFunction(ra.Context(), &lambdaapi.DeleteFunctionInput{
		FunctionName: &arn,
	})
	require.NoError(t, err)
}
