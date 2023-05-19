package connect

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/connect"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func getInstances(ctx parser.FileContext) []connect.Instance {

	connectresources := ctx.GetResourcesByType("AWS::Connect::Instance")
	var connects []connect.Instance
	for _, r := range connectresources {
		connects = append(connects, connect.Instance{
			Metadata:                      r.Metadata(),
			AttachmentStorageconfigs:      getstorageconfig(ctx, "ATTACHMENTS"),
			CallRecordingStorageconfigs:   getstorageconfig(ctx, "CALL_RECORDINGS"),
			ChatTranscriptsStorageconfigs: getstorageconfig(ctx, "CHAT_TRANSCRIPTS"),
			ExportedReportStorageconfigs:  getstorageconfig(ctx, "SCHEDULED_REPORTS"),
			MediaStreamsStorageconfigs:    getstorageconfig(ctx, "MEDIA_STREAMS"),
		})
	}
	return connects
}

func getstorageconfig(ctx parser.FileContext, resource string) []connect.StorageConfig {

	storageresource := ctx.GetResourcesByType("AWS::Connect::InstanceStorageConfig")
	var storagrconfig []connect.StorageConfig
	for _, r := range storageresource {
		if r.GetProperty("ResourceType").AsString() == resource {
			var key defsecTypes.StringValue
			if resource == "MEDIA_STREAMS" {
				if configprop := r.GetProperty("KinesisVideoStreamConfig"); configprop.IsNotNil() {
					if encrypprop := configprop.GetProperty("EncryptionConfig"); encrypprop.IsNotNil() {
						key = encrypprop.GetStringProperty("KeyId")
					}
				}
			} else {
				if s3configprop := r.GetProperty("S3Config"); s3configprop.IsNotNil() {
					if encrypprop := s3configprop.GetProperty("EncryptionConfig"); encrypprop.IsNotNil() {
						key = encrypprop.GetStringProperty("KeyId")
					}
				}
			}
			storagrconfig = append(storagrconfig, connect.StorageConfig{
				Metadata: r.Metadata(),
				KmsKeyId: key,
			})
		}

	}
	return storagrconfig
}
