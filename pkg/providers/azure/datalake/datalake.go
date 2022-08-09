package datalake

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type DataLake struct {
	Stores []Store
}

type Store struct {
	defsecTypes.Metadata
	EnableEncryption defsecTypes.BoolValue
}
