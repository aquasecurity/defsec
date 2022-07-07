package iam

import (
	"fmt"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/state"
	iamapi "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func (a *adapter) adaptUsers(state *state.State) error {

	a.Tracker().SetServiceLabel("Discovering users...")

	var nativeUsers []iamtypes.User

	input := &iamapi.ListUsersInput{}
	for {
		usersOutput, err := a.api.ListUsers(a.Context(), input)
		if err != nil {
			return err
		}
		nativeUsers = append(nativeUsers, usersOutput.Users...)
		a.Tracker().SetTotalResources(len(nativeUsers))
		if !usersOutput.IsTruncated {
			break
		}
		input.Marker = usersOutput.Marker
	}

	a.Tracker().SetServiceLabel("Adapting users...")

	for _, apiUser := range nativeUsers {
		user, err := a.adaptUser(apiUser)
		if err != nil {
			return err
		}
		state.AWS.IAM.Users = append(state.AWS.IAM.Users, *user)
		a.Tracker().IncrementResource()
	}

	return nil
}

func (a *adapter) adaptUser(apiUser iamtypes.User) (*iam.User, error) {

	if apiUser.Arn == nil {
		return nil, fmt.Errorf("user arn not specified")
	}
	if apiUser.UserName == nil {
		return nil, fmt.Errorf("user name not specified")
	}

	metadata := a.CreateMetadataFromARN(*apiUser.Arn)
	var groups []iam.Group

	{
		input := &iamapi.ListGroupsForUserInput{
			UserName: apiUser.UserName,
		}
		for {
			output, err := a.api.ListGroupsForUser(a.Context(), input)
			if err != nil {
				return nil, err
			}
			for _, apiGroup := range output.Groups {
				group, err := a.adaptGroup(apiGroup, nil)
				if err != nil {
					return nil, err
				}
				groups = append(groups, *group)
			}
			if !output.IsTruncated {
				break
			}
			input.Marker = output.Marker
		}
	}

	var policies []iam.Policy
	{
		input := &iamapi.ListAttachedUserPoliciesInput{
			UserName: apiUser.UserName,
		}
		for {
			policiesOutput, err := a.api.ListAttachedUserPolicies(a.Context(), input)
			if err != nil {
				return nil, err
			}

			for _, apiPolicy := range policiesOutput.AttachedPolicies {
				policy, err := a.adaptAttachedPolicy(apiPolicy)
				if err != nil {
					return nil, err
				}
				policies = append(policies, *policy)
			}

			if !policiesOutput.IsTruncated {
				break
			}
			input.Marker = policiesOutput.Marker
		}
	}

	return &iam.User{
		Metadata: metadata,
		Name:     types.String(*apiUser.UserName, metadata),
		Groups:   groups,
		Policies: policies,
	}, nil
}
