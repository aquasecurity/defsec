package kms

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type KMS struct {
	KeyRings []KeyRing
}

type KeyRing struct {
	Metadata defsecTypes.Metadata
	Keys     []Key
}

type Key struct {
	Metadata              defsecTypes.Metadata
	RotationPeriodSeconds defsecTypes.IntValue
}
