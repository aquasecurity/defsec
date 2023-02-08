package ec2

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Volume struct {
	Metadata               defsecTypes.Metadata
	VolumeId               defsecTypes.StringValue
	Attachments            []Attachment
	Encryption             Encryption
	EbsEncryptionByDefault defsecTypes.BoolValue
	EbsDefaultKmsKeyId     defsecTypes.StringValue
	Tags                   []Tags
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

type Attachment struct {
	Metadata   defsecTypes.Metadata
	InstanceId defsecTypes.StringValue
}

type Snapshot struct {
	Metadata                defsecTypes.Metadata
	VolumeId                defsecTypes.StringValue
	Ownerid                 defsecTypes.StringValue
	SnapshotId              defsecTypes.StringValue
	Encrypted               defsecTypes.BoolValue
	Tags                    []Tags
	CreateVolumePermissions []CreateVolumePermission
}

type Tags struct {
	Metadata defsecTypes.Metadata
}

type CreateVolumePermission struct {
	Metadata defsecTypes.Metadata
}
