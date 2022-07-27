package iam

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/state"
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

	return nil
}
