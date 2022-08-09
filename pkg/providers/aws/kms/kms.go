package kms

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type KMS struct {
	Keys []Key
}

const (
	KeyUsageSignAndVerify = "SIGN_VERIFY"
)

type Key struct {
	defsecTypes.Metadata
	Usage           defsecTypes.StringValue
	RotationEnabled defsecTypes.BoolValue
}
