package timestreamwrite

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Timestream_write struct {
	ListDatabases []Databases
}

type Databases struct {
	Metadata defsecTypes.Metadata
	Arn      defsecTypes.StringValue
	KmsKeyID defsecTypes.StringValue
}
