package kms

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type KMS struct {
	KeyRings []KeyRing
}

type KeyRing struct {
	defsecTypes.Metadata
	Keys []Key
}

type Key struct {
	defsecTypes.Metadata
	RotationPeriodSeconds defsecTypes.IntValue
}
