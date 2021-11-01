package kms

import "github.com/aquasecurity/defsec/types"

type KMS struct {
	Keys []Key
}

const (
	KeyUsageSignAndVerify = "SIGN_VERIFY"
)

type Key struct {
	Usage           types.StringValue
	RotationEnabled types.BoolValue
}
