package iam

import (
	"fmt"
	"strings"

	"github.com/liamg/iamgo"

	rapido "github.com/aquasecurity/defsec/internal/adapters/rapido"
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/state"
	iamapi "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func (a *adapter) adaptPolicies(state *state.State) error {

	a.Tracker().SetServiceLabel("Discovering policies...")

	var nativePolicies []iamtypes.Policy

	input := &iamapi.ListPoliciesInput{
		Scope: iamtypes.PolicyScopeTypeLocal,
	}
	for {
		policiesOutput, err := a.api.ListPolicies(a.Context(), input)
		if err != nil {
			return err
		}
		nativePolicies = append(nativePolicies, policiesOutput.Policies...)
		a.Tracker().SetTotalResources(len(nativePolicies))
		if !policiesOutput.IsTruncated {
			break
		}
		input.Marker = policiesOutput.Marker
	}

	a.Tracker().SetServiceLabel("Adapting policies...")

	state.AWS.IAM.Policies = rapido.ConcurrentAdapt(func(apiPolicy iamtypes.Policy) *iam.Policy {

		policy, err := a.adaptPolicy(apiPolicy)
		if err != nil {
			a.Debug("Failed to adapt role '%s': %s", *apiPolicy.Arn, err)
			return nil
		}

		a.Tracker().IncrementResource()

		return policy
	}, nativePolicies, a.RootAdapter.Logger())
	return nil
}

func (a *adapter) adaptPolicy(apiPolicy iamtypes.Policy) (*iam.Policy, error) {

	if apiPolicy.Arn == nil {
		return nil, fmt.Errorf("policy arn not specified")
	}
	if apiPolicy.PolicyName == nil {
		return nil, fmt.Errorf("policy name not specified")
	}

	output, err := a.api.GetPolicyVersion(a.Context(), &iamapi.GetPolicyVersionInput{
		PolicyArn: apiPolicy.Arn,
		VersionId: apiPolicy.DefaultVersionId,
	})
	if err != nil {
		return nil, err
	}

	metadata := a.CreateMetadataFromARN(*apiPolicy.Arn)

	document, err := iamgo.ParseString(*output.PolicyVersion.Document)
	if err != nil {
		return nil, err
	}

	return &iam.Policy{
		Metadata: metadata,
		Name:     types.String(*apiPolicy.PolicyName, metadata),
		Document: iam.Document{
			Metadata: metadata,
			Parsed:   *document,
		},
		Builtin: types.Bool(strings.HasPrefix(*apiPolicy.Arn, "arn:aws:iam::aws:"), metadata),
	}, nil
}

func (a *adapter) adaptAttachedPolicy(apiPolicy iamtypes.AttachedPolicy) (*iam.Policy, error) {

	if apiPolicy.PolicyArn == nil {
		return nil, fmt.Errorf("policy arn not specified")
	}
	if apiPolicy.PolicyName == nil {
		return nil, fmt.Errorf("policy name not specified")
	}

	policyOutput, err := a.api.GetPolicy(a.Context(), &iamapi.GetPolicyInput{
		PolicyArn: apiPolicy.PolicyArn,
	})
	if err != nil {
		return nil, err
	}

	return a.adaptPolicy(*policyOutput.Policy)
}
