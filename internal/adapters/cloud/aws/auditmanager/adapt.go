package auditmanager

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/auditmanager"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/auditmanager"
	types "github.com/aws/aws-sdk-go-v2/service/auditmanager/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "appflow"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {
	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())

	var err error
	state.AWS.Auditmanager.Settings, err = a.getAuditManager()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getAuditManager() (auditmanager.Setting, error) {
	a.Tracker().SetServiceLabel(" Auditmanager settings...")

	var input api.GetSettingsInput
	var auditmanagerapi types.Settings
	var Setting auditmanager.Setting

	output, err := a.api.GetSettings(a.Context(), &input)
	if err != nil {
		return Setting, err
	}

	auditmanagerapi = *output.Settings

	metadata := a.CreateMetadata(*auditmanagerapi.KmsKey)
	Setting = auditmanager.Setting{
		Metadata: metadata,
		KmsKey:   defsecTypes.String(*auditmanagerapi.KmsKey, metadata),
	}

	return Setting, nil

}
