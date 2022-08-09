package datalake

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type DataLake struct {
	Stores []Store
}

type Store struct {
	types2.Metadata
	EnableEncryption types2.BoolValue
}
