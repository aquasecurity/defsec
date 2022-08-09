package storage

import (
	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Storage struct {
	Buckets []Bucket
}

type Bucket struct {
	types2.Metadata
	Name                           types2.StringValue
	Location                       types2.StringValue
	EnableUniformBucketLevelAccess types2.BoolValue
	Members                        []iam.Member
	Bindings                       []iam.Binding
}
