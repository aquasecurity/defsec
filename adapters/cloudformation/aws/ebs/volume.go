package ebs

import (
	"github.com/aquasecurity/defsec/provider/aws/ebs"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

func getVolumes(ctx parser.FileContext) (volumes []ebs.Volume) {

	volumeResources := ctx.GetResourceByType("AWS::EC2::Volume")
	for _, r := range volumeResources {

		volume := ebs.Volume{
			Metadata: r.Metadata(),
			Encryption: ebs.Encryption{
				Enabled:  r.GetBoolProperty("Encrypted"),
				KMSKeyID: r.GetStringProperty("KmsKeyId"),
			},
		}

		volumes = append(volumes, volume)
	}
	return volumes
}
