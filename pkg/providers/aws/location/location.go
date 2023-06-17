package location

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Location struct {
	GeoFenceCollections []GeoFenceCollection
	Trackers            []Tracker
}

type GeoFenceCollection struct {
	Metadata defsecTypes.Metadata
	KmsKeyId defsecTypes.StringValue
}

type Tracker struct {
	Metadata defsecTypes.Metadata
	KmsKeyId defsecTypes.StringValue
}
