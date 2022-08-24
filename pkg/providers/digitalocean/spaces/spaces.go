package spaces

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Spaces struct {
	Buckets []Bucket
}

type Bucket struct {
	defsecTypes.Metadata
	Name         defsecTypes.StringValue
	Objects      []Object
	ACL          defsecTypes.StringValue
	ForceDestroy defsecTypes.BoolValue
	Versioning   Versioning
}

type Versioning struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}

type Object struct {
	defsecTypes.Metadata
	ACL defsecTypes.StringValue
}
