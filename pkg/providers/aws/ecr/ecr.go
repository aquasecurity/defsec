package ecr

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type ECR struct {
	Repositories []Repository
}

type Repository struct {
	types2.Metadata
	ImageScanning      ImageScanning
	ImageTagsImmutable types2.BoolValue
	Policies           []iam.Policy
	Encryption         Encryption
}

type ImageScanning struct {
	types2.Metadata
	ScanOnPush types2.BoolValue
}

const (
	EncryptionTypeKMS    = "KMS"
	EncryptionTypeAES256 = "AES256"
)

type Encryption struct {
	types2.Metadata
	Type     types2.StringValue
	KMSKeyID types2.StringValue
}
