package connect

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/connect"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) connect.Connect {
	return connect.Connect{
		Instances: adaptInstances(modules),
	}
}

func adaptInstances(modules terraform.Modules) []connect.Instance {
	var connects []connect.Instance
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_connect_instance") {
			connects = append(connects, connect.Instance{
				Metadata:                      resource.GetMetadata(),
				AttachmentStorageconfigs:      getstorageconfig(resource, module, "ATTACHMENTS"),
				CallRecordingStorageconfigs:   getstorageconfig(resource, module, "CALL_RECORDINGS"),
				ChatTranscriptsStorageconfigs: getstorageconfig(resource, module, "CHAT_TRANSCRIPTS"),
				ExportedReportStorageconfigs:  getstorageconfig(resource, module, "SCHEDULED_REPORTS"),
				MediaStreamsStorageconfigs:    getstorageconfig(resource, module, "MEDIA_STREAMS"),
			})
		}
	}
	return connects
}

func getstorageconfig(resource *terraform.Block, module *terraform.Module, restype string) []connect.StorageConfig {

	storageres := module.GetReferencingResources(resource, "aws_connect_instance_storage_config", " instance_id")
	var sc []connect.StorageConfig
	for _, res := range storageres {
		if resource.GetAttribute("resource_type").Value().AsString() == restype {
			var key defsecTypes.StringValue
			for _, r := range resource.GetBlocks("storage_config") {
				if restype == "MEDIA_STREAMS" {
					if configblock := r.GetBlock("kinesis_video_stream_config"); configblock.IsNotNil() {
						if encrypblock := configblock.GetBlock("encryption_config"); encrypblock.IsNotNil() {
							key = encrypblock.GetAttribute("key_id").AsStringValueOrDefault("", encrypblock)
						}
					}
				} else {
					if configblock := r.GetBlock("s3_config"); configblock.IsNotNil() {
						if encrypblock := configblock.GetBlock("encryption_config"); encrypblock.IsNotNil() {
							key = encrypblock.GetAttribute("key_id").AsStringValueOrDefault("", encrypblock)
						}
					}
				}
				sc = append(sc, connect.StorageConfig{
					Metadata: res.GetMetadata(),
					KmsKeyId: key,
				})
			}
		}

	}
	return sc
}
