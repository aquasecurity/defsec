package guardduty

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/guardduty"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
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
	return "guardduty"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.GuardDuty.Detectors, err = a.getDetectors()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getDetectors() ([]guardduty.Detector, error) {

	a.Tracker().SetServiceLabel("Discovering detectors...")

	var apiDetectors []string
	var input api.ListDetectorsInput
	for {
		output, err := a.api.ListDetectors(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiDetectors = append(apiDetectors, output.DetectorIds...)
		a.Tracker().SetTotalResources(len(apiDetectors))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting dettectors...")
	return concurrency.Adapt(apiDetectors, a.RootAdapter, a.adaptDetector), nil
}

func (a *adapter) adaptDetector(detector string) (*guardduty.Detector, error) {
	metadata := a.CreateMetadata(detector)

	output, err := a.api.GetDetector(a.Context(), &api.GetDetectorInput{
		DetectorId: &detector,
	})
	if err != nil {
		return nil, err
	}

	account, err := a.api.GetAdministratorAccount(a.Context(), &api.GetAdministratorAccountInput{
		DetectorId: &detector,
	})
	if err != nil {
		return nil, err
	}

	status := defsecTypes.Bool(true, metadata)
	if output.Status == types.DetectorStatusDisabled {
		status = defsecTypes.Bool(false, metadata)
	}

	return &guardduty.Detector{
		Metadata:               metadata,
		Status:                 status,
		PublishingDestinations: a.getPublishingDestinations(detector),
		Findings:               a.getFindings(detector),
		MasterAccount: guardduty.MasterAccount{
			Metadata:           metadata,
			RelationshipStatus: defsecTypes.String(*account.Administrator.RelationshipStatus, metadata),
			AccountId:          defsecTypes.String(*account.Administrator.AccountId, metadata),
		},
	}, nil
}

func (a *adapter) getPublishingDestinations(detector string) []guardduty.PublishingDestination {

	var publishingdestinations []guardduty.PublishingDestination

	detinations, err := a.api.ListPublishingDestinations(a.Context(), &api.ListPublishingDestinationsInput{
		DetectorId: &detector,
	})
	if err != nil {
		return publishingdestinations
	}
	for _, destination := range detinations.Destinations {
		output, _ := a.api.DescribePublishingDestination(a.Context(), &api.DescribePublishingDestinationInput{
			DetectorId:    &detector,
			DestinationId: destination.DestinationId,
		})

		metadata := a.CreateMetadata(*destination.DestinationId)
		publishingdestinations = append(publishingdestinations, guardduty.PublishingDestination{
			Metadata:  metadata,
			KmsKeyArn: defsecTypes.String(*output.DestinationProperties.KmsKeyArn, metadata),
		})

	}
	return publishingdestinations
}

func (a *adapter) getFindings(detector string) []guardduty.Finding {

	var findings []guardduty.Finding

	apifindings, err := a.api.ListFindings(a.Context(), &api.ListFindingsInput{
		DetectorId: &detector,
	})
	if err != nil {
		return findings
	}

	output, _ := a.api.GetFindings(a.Context(), &api.GetFindingsInput{
		DetectorId: &detector,
		FindingIds: apifindings.FindingIds,
	})
	for _, finding := range output.Findings {
		metadata := a.CreateMetadata(*finding.Id)
		findings = append(findings, guardduty.Finding{
			Metadata:  metadata,
			CreatedAt: defsecTypes.String(*finding.CreatedAt, metadata),
		})
	}

	return findings
}
