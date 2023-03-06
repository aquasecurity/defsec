package kinesisvideo

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/kinesisvideo"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getStreamInfo(ctx parser.FileContext) (streaminfo []kinesisvideo.StreamInfo) {

	streamResources := ctx.GetResourcesByType("AWS::KinesisVideo::Stream")

	for _, r := range streamResources {
		streaminfos := kinesisvideo.StreamInfo{
			Metadata: r.Metadata(),
			KmsKeyId: r.GetStringProperty("KmsKeyId"),
		}

		streaminfo = append(streaminfo, streaminfos)
	}

	return streaminfo
}
