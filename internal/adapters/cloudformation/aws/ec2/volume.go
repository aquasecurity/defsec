package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func getVolumes(ctx parser.FileContext) (volumes []ec2.Volume) {

	volumeResources := ctx.GetResourcesByType("AWS::EC2::Volume")
	for _, r := range volumeResources {

		var tags []ec2.Tags
		for _, res := range r.GetProperty("Tags").AsList() {
			tags = append(tags, ec2.Tags{
				Metadata: res.Metadata(),
			})
		}

		volume := ec2.Volume{
			Metadata: r.Metadata(),
			VolumeId: r.GetStringProperty("VolumeId"),
			Encryption: ec2.Encryption{
				Metadata: r.Metadata(),
				Enabled:  r.GetBoolProperty("Encrypted"),
				KMSKeyID: r.GetStringProperty("KmsKeyId"),
			},
			Attachments:            getattachemnts(ctx),
			EbsEncryptionByDefault: defsecTypes.BoolDefault(false, r.Metadata()),
			EbsDefaultKmsKeyId:     defsecTypes.String("", r.Metadata()),
			Tags:                   tags,
		}

		volumes = append(volumes, volume)
	}
	return volumes
}

func getattachemnts(ctx parser.FileContext) []ec2.Attachment {
	attachement := ctx.GetResourcesByType("AWS::EC2::VolumeAttachment")
	var VA []ec2.Attachment
	for _, r := range attachement {
		VA = append(VA, ec2.Attachment{
			Metadata:   r.Metadata(),
			InstanceId: r.GetStringProperty("InstanceId"),
		})
	}
	return VA
}

func getSnapShots(ctx parser.FileContext) (snapshots []ec2.Snapshot) {

	snapshotResources := ctx.GetResourcesByType("AWS::EC2::Instance")
	for _, r := range snapshotResources {

		var snapshotidval defsecTypes.StringValue
		var encryptedval defsecTypes.BoolValue

		if BDM := r.GetProperty("BlockDeviceMappings"); BDM.IsNotNil() {
			if EBS := BDM.GetProperty("EBS"); EBS.IsNotNil() {
				snapshotidval = EBS.GetStringProperty("SnapshotId")
				encryptedval = EBS.GetBoolProperty("Encrypted")
			}
		}

		snapshot := ec2.Snapshot{
			Metadata:   r.Metadata(),
			SnapshotId: snapshotidval,
			Encrypted:  encryptedval,
			VolumeId:   defsecTypes.String("", r.Metadata()),
			Ownerid:    defsecTypes.String("", r.Metadata()),
		}

		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}
