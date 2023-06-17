package location

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/location"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getFenceCollections(ctx parser.FileContext) []location.GeoFenceCollection {

	var collections []location.GeoFenceCollection

	for _, r := range ctx.GetResourcesByType("AWS::Location::GeofenceCollection") {
		collections = append(collections, location.GeoFenceCollection{
			Metadata: r.Metadata(),
			KmsKeyId: r.GetStringProperty("KmsKeyId"),
		})
	}
	return collections
}

func getTrackers(ctx parser.FileContext) []location.Tracker {

	var trackers []location.Tracker

	for _, r := range ctx.GetResourcesByType("AWS::Location::Tracker") {
		trackers = append(trackers, location.Tracker{
			Metadata: r.Metadata(),
			KmsKeyId: r.GetStringProperty("KmsKeyId"),
		})
	}
	return trackers

}
