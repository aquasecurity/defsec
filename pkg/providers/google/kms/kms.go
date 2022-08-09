package kms

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type KMS struct {
	KeyRings []KeyRing
}

type KeyRing struct {
	types2.Metadata
	Keys []Key
}

type Key struct {
	types2.Metadata
	RotationPeriodSeconds types2.IntValue
}
