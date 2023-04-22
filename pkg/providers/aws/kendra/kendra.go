package kendra

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Kendra struct {
	ListIndices []ListIndices
}

type ListIndices struct {
	Metadata defsecTypes.Metadata
	KmsKey   KmsKey
}

type KmsKey struct {
	Metadata defsecTypes.Metadata
	KmsKeyId defsecTypes.StringValue
}
