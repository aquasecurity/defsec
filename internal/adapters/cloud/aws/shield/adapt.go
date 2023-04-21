package shield

import (
	"time"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/shield"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/shield"
	aatypes "github.com/aws/aws-sdk-go-v2/service/shield/types"
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
	return "shield"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Shield.DescribeSubscription, err = a.getDescribeSubscription()
	if err != nil {
		return err
	}

	state.AWS.Shield.DescribeEmergencyContactSettings, err = a.getContactSettings()
	if err != nil {
		return err
	}

	state.AWS.Shield.ListProtections, err = a.getProtections()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getDescribeSubscription() (shield.Subscription, error) {

	var input api.DescribeSubscriptionInput

	a.Tracker().SetServiceLabel("Discovering subscription...")

	describesubscription := shield.Subscription{
		Metadata:  defsecTypes.NewUnmanagedMetadata(),
		EndTime:   defsecTypes.TimeDefault(time.Now(), defsecTypes.NewUnmanagedMetadata()),
		AutoRenew: defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
	}

	output, err := a.api.DescribeSubscription(a.Context(), &input)
	if err != nil {
		return describesubscription, err
	}

	metadata := a.CreateMetadataFromARN(*output.Subscription.SubscriptionArn)

	var autorenew string
	if output.Subscription.AutoRenew != "ENABLED" {
		autorenew = "DISABLED"
	}

	return shield.Subscription{
		Metadata:  metadata,
		EndTime:   defsecTypes.Time(*output.Subscription.EndTime, metadata),
		AutoRenew: defsecTypes.String(autorenew, metadata),
	}, nil
}

func (a *adapter) getContactSettings() ([]shield.ContactSettings, error) {

	a.Tracker().SetServiceLabel("Discovering Contact Settings...")

	var apiContactSettings []aatypes.EmergencyContact
	var input api.DescribeEmergencyContactSettingsInput
	for {
		output, err := a.api.DescribeEmergencyContactSettings(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiContactSettings = append(apiContactSettings, output.EmergencyContactList...)
		a.Tracker().SetTotalResources(len(apiContactSettings))
		if output.EmergencyContactList == nil {
			break
		}
	}

	a.Tracker().SetServiceLabel("Adapting Contact Settings...")
	return concurrency.Adapt(apiContactSettings, a.RootAdapter, a.adaptContactSettings), nil
}

func (a *adapter) adaptContactSettings(apiContactSettings aatypes.EmergencyContact) (*shield.ContactSettings, error) {

	metadata := a.CreateMetadata(*apiContactSettings.EmailAddress)

	return &shield.ContactSettings{
		Metadata: metadata,
	}, nil
}

func (a *adapter) getProtections() ([]shield.Protections, error) {

	a.Tracker().SetServiceLabel("Discovering Protections...")

	var apiProtections []aatypes.Protection
	var input api.ListProtectionsInput
	for {
		output, err := a.api.ListProtections(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiProtections = append(apiProtections, output.Protections...)
		a.Tracker().SetTotalResources(len(apiProtections))
		if output.Protections == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting Protections...")
	return concurrency.Adapt(apiProtections, a.RootAdapter, a.adaptProtections), nil
}

func (a *adapter) adaptProtections(apiProtections aatypes.Protection) (*shield.Protections, error) {

	metadata := a.CreateMetadata(*apiProtections.ProtectionArn)

	return &shield.Protections{
		Metadata: metadata,
	}, nil
}
