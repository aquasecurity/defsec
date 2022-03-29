package datalake

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type DataLake struct {
	types.Metadata
	Stores []Store
}

type Store struct {
	types.Metadata
	EnableEncryption types.BoolValue
}
