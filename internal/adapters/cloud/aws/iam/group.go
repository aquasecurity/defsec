package iam

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/state"
	iamapi "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func (a *adapter) adaptGroups(state *state.State) error {

	a.Tracker().SetServiceLabel("Discovering groups...")

	var nativeGroups []iamtypes.Group

	input := &iamapi.ListGroupsInput{}
	for {
		groupsOutput, err := a.api.ListGroups(a.Context(), input)
		if err != nil {
			return err
		}
		nativeGroups = append(nativeGroups, groupsOutput.Groups...)
		a.Tracker().SetTotalResources(len(nativeGroups))
		if !groupsOutput.IsTruncated {
			break
		}
		input.Marker = groupsOutput.Marker
	}

	a.Tracker().SetServiceLabel("Adapting groups...")

	state.AWS.IAM.Groups = concurrency.AdaptWithStrategy(nativeGroups, state, a.RootAdapter, a.adaptGroup)
	return nil
}

func (a *adapter) adaptGroup(apiGroup iamtypes.Group, state *state.State) (*iam.Group, error) {

	if apiGroup.Arn == nil {
		return nil, fmt.Errorf("group arn not specified")
	}
	if apiGroup.GroupName == nil {
		return nil, fmt.Errorf("group name not specified")
	}

	metadata := a.CreateMetadataFromARN(*apiGroup.Arn)

	var policies []iam.Policy
	{
		input := &iamapi.ListAttachedGroupPoliciesInput{
			GroupName: apiGroup.GroupName,
		}
		for {
			policiesOutput, err := a.api.ListAttachedGroupPolicies(a.Context(), input)
			if err != nil {
				a.Debug("Failed to locate policies attached to group '%s': %s", *apiGroup.GroupName, err)
				break
			}

			for _, apiPolicy := range policiesOutput.AttachedPolicies {
				policy, err := a.adaptAttachedPolicy(apiPolicy)
				if err != nil {
					a.Debug("Failed to adapt policy attached to group '%s': %s", *apiGroup.GroupName, err)
					continue
				}
				policies = append(policies, *policy)
			}

			if !policiesOutput.IsTruncated {
				break
			}
			input.Marker = policiesOutput.Marker
		}
	}

	var users []iam.User
	if state != nil {
		for _, user := range state.AWS.IAM.Users {
			for _, userGroup := range user.Groups {
				if userGroup.Name.EqualTo(*apiGroup.GroupName) {
					users = append(users, user)
				}
			}
		}
	}
	a.Tracker().IncrementResource()
	return &iam.Group{
		Metadata: metadata,
		Name:     types.String(*apiGroup.GroupName, metadata),
		Users:    users,
		Policies: policies,
	}, nil
}
