package iam

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
	iamapi "github.com/aws/aws-sdk-go-v2/service/iam"
)

type adapter struct {
	*aws.RootAdapter
	api *iamapi.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "iam"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = iamapi.NewFromConfig(root.SessionConfig())

	if err := a.adaptPasswordPolicy(state); err != nil {
		return err
	}

	if err := a.adaptPolicies(state); err != nil {
		return err
	}

	if err := a.adaptRoles(state); err != nil {
		return err
	}

	if err := a.adaptUsers(state); err != nil {
		return err
	}

	// groups must be transformed last because it depends on users
	if err := a.adaptGroups(state); err != nil {
		return err
	}

	if err := a.adaptServerCertificates(state); err != nil {
		return err
	}

	if err := a.adaptVirtualMfadevices(state); err != nil {
		return err
	}

	return nil
}

func (a *adapter) adaptPasswordPolicy(state *state.State) error {

	a.Tracker().SetServiceLabel("Checking password policy...")

	output, err := a.api.GetAccountPasswordPolicy(a.Context(), &iamapi.GetAccountPasswordPolicyInput{})
	if err != nil {
		a.Debug("Failed to adapt account password policy: %s", err)
		return nil
	}
	a.Tracker().SetTotalResources(1)
	policy := output.PasswordPolicy
	metadata := a.CreateMetadata("passwordpolicy")
	reusePrevention := 0
	if policy.PasswordReusePrevention != nil {
		reusePrevention = int(*policy.PasswordReusePrevention)
	}

	maxAge := 0
	if policy.MaxPasswordAge != nil {
		maxAge = int(*policy.MaxPasswordAge)
	}
	minimumLength := 0
	if policy.MinimumPasswordLength != nil {
		minimumLength = int(*policy.MinimumPasswordLength)
	}
	state.AWS.IAM.PasswordPolicy = iam.PasswordPolicy{
		Metadata:                   metadata,
		ReusePreventionCount:       types.Int(reusePrevention, metadata),
		RequireLowercase:           types.Bool(policy.RequireLowercaseCharacters, metadata),
		RequireUppercase:           types.Bool(policy.RequireUppercaseCharacters, metadata),
		RequireNumbers:             types.Bool(policy.RequireNumbers, metadata),
		RequireSymbols:             types.Bool(policy.RequireSymbols, metadata),
		ExpirePasswords:            types.Bool(policy.ExpirePasswords, metadata),
		MaxAgeDays:                 types.Int(maxAge, metadata),
		MinimumLength:              types.Int(minimumLength, metadata),
		AllowUsersToChangePassword: types.Bool(policy.AllowUsersToChangePassword, metadata),
	}

	return nil
}
