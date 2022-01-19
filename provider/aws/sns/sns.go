package sns

import "github.com/aquasecurity/defsec/types"

type SNS struct {
	types.Metadata
	Topics []Topic
}

type Topic struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	KMSKeyID types.StringValue
}

func (v *Topic) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *Topic) GetRawValue() interface{} {
	return nil
}
