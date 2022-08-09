package iam

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/state"
	iamapi "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func (a *adapter) adaptRoles(state *state.State) error {

	a.Tracker().SetServiceLabel("Discovering roles...")

	var nativeRoles []iamtypes.Role

	input := &iamapi.ListRolesInput{}
	for {
		rolesOutput, err := a.api.ListRoles(a.Context(), input)
		if err != nil {
			return err
		}
		nativeRoles = append(nativeRoles, rolesOutput.Roles...)
		a.Tracker().SetTotalResources(len(nativeRoles))
		if !rolesOutput.IsTruncated {
			break
		}
		input.Marker = rolesOutput.Marker
	}

	a.Tracker().SetServiceLabel("Adapting roles...")

	for _, apiRole := range nativeRoles {
		user, err := a.adaptRole(apiRole)
		if err != nil {
			a.Debug("Failed to adapt role '%s': %s", *apiRole.Arn, err)
			continue
		}
		state.AWS.IAM.Roles = append(state.AWS.IAM.Roles, *user)
		a.Tracker().IncrementResource()
	}

	return nil
}

func (a *adapter) adaptRole(apiRole iamtypes.Role) (*iam.Role, error) {

	if apiRole.Arn == nil {
		return nil, fmt.Errorf("role arn not specified")
	}
	if apiRole.RoleName == nil {
		return nil, fmt.Errorf("role name not specified")
	}

	var policies []iam.Policy

	input := &iamapi.ListAttachedRolePoliciesInput{
		RoleName: apiRole.RoleName,
	}
	for {
		policiesOutput, err := a.api.ListAttachedRolePolicies(a.Context(), input)
		if err != nil {
			a.Debug("Failed to locate policies attached to role '%s': %s", *apiRole.RoleName, err)
			break
		}

		for _, apiPolicy := range policiesOutput.AttachedPolicies {
			policy, err := a.adaptAttachedPolicy(apiPolicy)
			if err != nil {
				a.Debug("Failed to adapt policy attached to role '%s': %s", *apiRole.RoleName, err)
				continue
			}
			policies = append(policies, *policy)
		}

		if !policiesOutput.IsTruncated {
			break
		}
		input.Marker = policiesOutput.Marker
	}

	metadata := a.CreateMetadataFromARN(*apiRole.Arn)

	return &iam.Role{
		Metadata: metadata,
		Name:     types.String(*apiRole.RoleName, metadata),
		Policies: policies,
	}, nil
}
