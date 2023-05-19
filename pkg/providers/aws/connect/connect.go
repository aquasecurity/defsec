package connect

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	types "github.com/aws/aws-sdk-go-v2/service/connect/types"
)

type Connect struct {
	Instances []Instance
}

type Instance struct {
	Metadata                      defsecTypes.Metadata
	AttachmentStorageconfigs      []StorageConfig
	CallRecordingStorageconfigs   []StorageConfig
	MediaStreamsStorageconfigs    []StorageConfig
	ExportedReportStorageconfigs  []StorageConfig
	ChatTranscriptsStorageconfigs []StorageConfig
}

type StorageConfig struct {
	Metadata defsecTypes.Metadata
	KmsKeyId defsecTypes.StringValue
}

var (
	ResourceType = [5]types.InstanceStorageResourceType{"ATTACHMENTS", "CALL_RECORDINGS", "CHAT_TRANSCRIPTS", "SCHEDULED_REPORTS", "MEDIA_STREAMS"}
)

// Attachments is not supported no
