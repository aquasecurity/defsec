package location

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/location"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/location"
	"github.com/aws/aws-sdk-go-v2/service/location/types"
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
	return "location"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Location.GeoFenceCollections, err = a.getGeoFenceCollections()
	if err != nil {
		return err
	}

	state.AWS.Location.Trackers, err = a.gettrackers()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getGeoFenceCollections() ([]location.GeoFenceCollection, error) {

	a.Tracker().SetServiceLabel("Discovering fence collections...")

	var apicollections []types.ListGeofenceCollectionsResponseEntry
	var input api.ListGeofenceCollectionsInput
	for {
		output, err := a.api.ListGeofenceCollections(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apicollections = append(apicollections, output.Entries...)
		a.Tracker().SetTotalResources(len(apicollections))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting fence collection...")
	return concurrency.Adapt(apicollections, a.RootAdapter, a.adaptFenceCollection), nil
}

func (a *adapter) adaptFenceCollection(collection types.ListGeofenceCollectionsResponseEntry) (*location.GeoFenceCollection, error) {
	metadata := a.CreateMetadata(*collection.CollectionName)

	output, err := a.api.DescribeGeofenceCollection(a.Context(), &api.DescribeGeofenceCollectionInput{
		CollectionName: collection.CollectionName,
	})
	if err != nil {
		return nil, err
	}
	return &location.GeoFenceCollection{
		Metadata: metadata,
		KmsKeyId: defsecTypes.String(*output.KmsKeyId, metadata),
	}, nil
}

func (a *adapter) gettrackers() ([]location.Tracker, error) {

	a.Tracker().SetServiceLabel("Discovering trackers...")

	var apitrackers []types.ListTrackersResponseEntry
	var input api.ListTrackersInput
	for {
		output, err := a.api.ListTrackers(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apitrackers = append(apitrackers, output.Entries...)
		a.Tracker().SetTotalResources(len(apitrackers))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting tracker...")
	return concurrency.Adapt(apitrackers, a.RootAdapter, a.adaptTracker), nil
}

func (a *adapter) adaptTracker(tracker types.ListTrackersResponseEntry) (*location.Tracker, error) {

	metadata := a.CreateMetadata(*tracker.TrackerName)

	output, err := a.api.DescribeTracker(a.Context(), &api.DescribeTrackerInput{
		TrackerName: tracker.TrackerName,
	})
	if err != nil {
		return nil, err
	}

	return &location.Tracker{
		Metadata: metadata,
		KmsKeyId: defsecTypes.String(*output.KmsKeyId, metadata),
	}, nil
}
