package kinesisvideo

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/kinesisvideo"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) kinesisvideo.Kinesisvideo {
	return kinesisvideo.Kinesisvideo{
		StreamInfoList: adaptStreamInfoList(modules),
	}
}

func adaptStreamInfoList(modules terraform.Modules) []kinesisvideo.StreamInfo {
	var streaminfo []kinesisvideo.StreamInfo
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_kinesis_video_stream") {
			streaminfo = append(streaminfo, adaptIndex(resource))
		}
	}
	return streaminfo
}

func adaptIndex(resource *terraform.Block) kinesisvideo.StreamInfo {

	index := kinesisvideo.StreamInfo{
		Metadata: resource.GetMetadata(),
		KmsKeyId: resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
	}

	return index
}
