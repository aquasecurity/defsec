package iam

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

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

	state.AWS.IAM.Users = concurrency.Adapt(nativeUsers, a.RootAdapter, a.adaptUser)
	return nil
}

func (a *adapter) getMFADevices(user iamtypes.User) ([]iam.MFADevice, error) {
	input := &iamapi.ListMFADevicesInput{
		Marker:   nil,
		UserName: user.UserName,
	}
	var apiDevices []iamtypes.MFADevice
	for {
		output, err := a.api.ListMFADevices(a.Context(), input)
		if err != nil {
			return nil, err
		}
		apiDevices = append(apiDevices, output.MFADevices...)
		if !output.IsTruncated {
			break
		}
		input.Marker = output.Marker
	}

	var devices []iam.MFADevice
	for _, apiDevice := range apiDevices {
		metadata := a.CreateMetadataFromARN(*apiDevice.SerialNumber)
		if !strings.HasPrefix(*apiDevice.SerialNumber, "arn:") {
			metadata = a.CreateMetadataFromARN(*user.Arn)
		}
		devices = append(devices, iam.MFADevice{
			Metadata: metadata,
		})
	}

	return devices, nil
}

func (a *adapter) getUserGroups(apiUser iamtypes.User) []iam.Group {
	var groups []iam.Group

	input := &iamapi.ListGroupsForUserInput{
		UserName: apiUser.UserName,
	}
	for {
		output, err := a.api.ListGroupsForUser(a.Context(), input)
		if err != nil {
			a.Debug("Failed to locate groups attached to user '%s': %s", *apiUser.UserName, err)
			break
		}
		for _, apiGroup := range output.Groups {
			group, err := a.adaptGroup(apiGroup, nil)
			if err != nil {
				a.Debug("Failed to adapt group attached to user '%s': %s", *apiUser.UserName, err)
				continue
			}
			groups = append(groups, *group)
		}
		if !output.IsTruncated {
			break
		}
		input.Marker = output.Marker
	}
	return groups
}

func (a *adapter) getUserPolicies(apiUser iamtypes.User) []iam.Policy {
	var policies []iam.Policy
	input := &iamapi.ListAttachedUserPoliciesInput{
		UserName: apiUser.UserName,
	}
	for {
		policiesOutput, err := a.api.ListAttachedUserPolicies(a.Context(), input)
		if err != nil {
			a.Debug("Failed to locate policies attached to user '%s': %s", *apiUser.UserName, err)
			break
		}

		for _, apiPolicy := range policiesOutput.AttachedPolicies {
			policy, err := a.adaptAttachedPolicy(apiPolicy)
			if err != nil {
				a.Debug("Failed to adapt policy attached to user '%s': %s", *apiUser.UserName, err)
				continue
			}
			policies = append(policies, *policy)
		}

		if !policiesOutput.IsTruncated {
			break
		}
		input.Marker = policiesOutput.Marker
	}
	return policies
}

func (a *adapter) getUserKeys(apiUser iamtypes.User) ([]iam.AccessKey, error) {

	var keys []iam.AccessKey
	metadata := a.CreateMetadataFromARN(*apiUser.Arn)
	input := iamapi.ListAccessKeysInput{
		UserName: apiUser.UserName,
	}
	for {
		output, err := a.api.ListAccessKeys(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		for _, apiAccessKey := range output.AccessKeyMetadata {

			lastUsed := defsecTypes.TimeUnresolvable(metadata)
			if output, err := a.api.GetAccessKeyLastUsed(a.Context(), &iamapi.GetAccessKeyLastUsedInput{
				AccessKeyId: apiAccessKey.AccessKeyId,
			}); err == nil {
				if output.AccessKeyLastUsed != nil && output.AccessKeyLastUsed.LastUsedDate != nil {
					lastUsed = defsecTypes.Time(*output.AccessKeyLastUsed.LastUsedDate, metadata)
				}
			}

			accessKeyId := defsecTypes.StringDefault("", metadata)
			if apiAccessKey.AccessKeyId != nil {
				accessKeyId = defsecTypes.String(*apiAccessKey.AccessKeyId, metadata)
			}

			creationDate := defsecTypes.TimeDefault(time.Now(), metadata)
			if apiAccessKey.CreateDate != nil {
				creationDate = defsecTypes.Time(*apiAccessKey.CreateDate, metadata)
			}

			keys = append(keys, iam.AccessKey{
				Metadata:     metadata,
				AccessKeyId:  accessKeyId,
				Active:       defsecTypes.Bool(apiAccessKey.Status == iamtypes.StatusTypeActive, metadata),
				CreationDate: creationDate,
				LastAccess:   lastUsed,
			})
		}
		if !output.IsTruncated {
			break
		}
		input.Marker = output.Marker
	}
	return keys, nil
}

func (a *adapter) adaptUser(apiUser iamtypes.User) (*iam.User, error) {

	if apiUser.Arn == nil {
		return nil, fmt.Errorf("user arn not specified")
	}
	if apiUser.UserName == nil {
		return nil, fmt.Errorf("user name not specified")
	}

	metadata := a.CreateMetadataFromARN(*apiUser.Arn)

	groups := a.getUserGroups(apiUser)

	policies := a.getUserPolicies(apiUser)

	keys, err := a.getUserKeys(apiUser)
	if err != nil {
		return nil, err
	}

	mfaDevices, err := a.getMFADevices(apiUser)
	if err != nil {
		return nil, err
	}

	lastAccess := defsecTypes.TimeUnresolvable(metadata)
	if apiUser.PasswordLastUsed != nil {
		lastAccess = defsecTypes.Time(*apiUser.PasswordLastUsed, metadata)
	}

	return &iam.User{
		Metadata:   metadata,
		Name:       defsecTypes.String(*apiUser.UserName, metadata),
		Groups:     groups,
		Policies:   policies,
		AccessKeys: keys,
		MFADevices: mfaDevices,
		LastAccess: lastAccess,
	}, nil
}
