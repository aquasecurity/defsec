package kinesis

import (
	"github.com/aquasecurity/defsec/provider/aws/kinesis"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

func getStreams(ctx parser.FileContext) (streams []kinesis.Stream) {

	streamResources := ctx.GetResourceByType("AWS::Kinesis::Stream")

	for _, r := range streamResources {

		stream := kinesis.Stream{
			Metadata: r.Metadata(),
			Encryption: kinesis.Encryption{
				Type:     r.GetStringProperty("StreamEncryption.EncryptionType"),
				KMSKeyID: r.GetStringProperty("StreamEncryption.KeyId"),
			},
		}

		streams = append(streams, stream)
	}

	return streams
}
