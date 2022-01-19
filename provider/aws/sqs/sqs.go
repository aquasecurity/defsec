package sqs

import (
	"github.com/aquasecurity/defsec/types"
)

type SQS struct {
	types.Metadata
	Queues []Queue
}

type Queue struct {
	types.Metadata
	Encryption Encryption
	Policies   []types.StringValue
}

type Encryption struct {
	types.Metadata
	KMSKeyID types.StringValue
}

func (v *Queue) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *Queue) GetRawValue() interface{} {
	return nil
}
