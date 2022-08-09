package ecr

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ECR struct {
	Repositories []Repository
}

type Repository struct {
	defsecTypes.Metadata
	ImageScanning      ImageScanning
	ImageTagsImmutable defsecTypes.BoolValue
	Policies           []iam.Policy
	Encryption         Encryption
}

type ImageScanning struct {
	defsecTypes.Metadata
	ScanOnPush defsecTypes.BoolValue
}

const (
	EncryptionTypeKMS    = "KMS"
	EncryptionTypeAES256 = "AES256"
)

type Encryption struct {
	defsecTypes.Metadata
	Type     defsecTypes.StringValue
	KMSKeyID defsecTypes.StringValue
}
