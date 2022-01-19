package ebs

import "github.com/aquasecurity/defsec/types"

type EBS struct {
	types.Metadata
	Volumes []Volume
}

type Volume struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}

func (c *Volume) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Volume) GetRawValue() interface{} {
	return nil
}
