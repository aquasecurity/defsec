package location

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/location"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) location.Location {
	return location.Location{
		GeoFenceCollections: getFenceCollections(cfFile),
		Trackers:            getTrackers(cfFile),
	}
}
