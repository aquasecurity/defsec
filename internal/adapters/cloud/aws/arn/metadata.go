package arn

import "github.com/aquasecurity/defsec/internal/types"

func (a ARN) Metadata() types.Metadata {
	return types.NewRemoteMetadata(a.String())
}
