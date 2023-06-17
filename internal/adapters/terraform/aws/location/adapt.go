package location

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/location"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) location.Location {
	return location.Location{
		GeoFenceCollections: adaptFenceCollections(modules),
		Trackers:            adaptTrackers(modules),
	}
}

func adaptFenceCollections(modules terraform.Modules) []location.GeoFenceCollection {
	var collections []location.GeoFenceCollection
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_location_geofence_collection") {
			collections = append(collections, location.GeoFenceCollection{
				Metadata: resource.GetMetadata(),
				KmsKeyId: resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
			})
		}
	}
	return collections
}

func adaptTrackers(modules terraform.Modules) []location.Tracker {
	var trackers []location.Tracker
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_location_tracker") {
			trackers = append(trackers, location.Tracker{
				Metadata: resource.GetMetadata(),
				KmsKeyId: resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
			})
		}
	}
	return trackers
}
