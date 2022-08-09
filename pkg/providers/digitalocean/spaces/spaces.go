package spaces

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Spaces struct {
	Buckets []Bucket
}

type Bucket struct {
	types2.Metadata
	Name         types2.StringValue
	Objects      []Object
	ACL          types2.StringValue
	ForceDestroy types2.BoolValue
	Versioning   Versioning
}

type Versioning struct {
	types2.Metadata
	Enabled types2.BoolValue
}

type Object struct {
	types2.Metadata
	ACL types2.StringValue
}
