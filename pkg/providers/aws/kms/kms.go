package kms

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type KMS struct {
	Keys []Key
}

const (
	KeyUsageSignAndVerify = "SIGN_VERIFY"
)

type Key struct {
	types2.Metadata
	Usage           types2.StringValue
	RotationEnabled types2.BoolValue
}
