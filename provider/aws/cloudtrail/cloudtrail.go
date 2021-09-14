package cloudtrail

import "github.com/aquasecurity/defsec/types"

type CloudTrail struct {
	Trails []Trail
}

type Trail struct {
	Name                    types.StringValue
	EnableLogFileValidation types.BoolValue
	IsMultiRegion           types.BoolValue
	KMSKeyID                types.StringValue
}
