package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/terraform"
	types "github.com/aquasecurity/defsec/pkg/types"
)

func adaptVolumes(modules terraform.Modules) []ec2.Volume {
	var volumes []ec2.Volume
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ebs_volume") {
			volumes = append(volumes, adaptVolume(resource, module))
		}
	}
	return volumes
}

func adaptSnapShots(modules terraform.Modules) []ec2.Snapshot {
	var snapshots []ec2.Snapshot
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ebs_snapshot") {
			snapshots = append(snapshots, adaptSnapShot(resource, module))
		}
	}
	return snapshots
}

func adaptVolume(resource *terraform.Block, module *terraform.Module) ec2.Volume {
	encryptedAttr := resource.GetAttribute("encrypted")
	encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, resource)

	kmsKeyAttr := resource.GetAttribute("kms_key_id")
	kmsKeyVal := kmsKeyAttr.AsStringValueOrDefault("", resource)

	idAttr := resource.GetAttribute("id")
	idVal := idAttr.AsStringValueOrDefault("", resource)

	var attachement []ec2.Attachment
	attachres := module.GetReferencingResources(resource, "aws_volume_attachment", " volume_id")
	for _, VA := range attachres {
		instanceidAttr := VA.GetAttribute("")
		instanceidVAl := instanceidAttr.AsStringValueOrDefault("", VA)
		attachement = append(attachement, ec2.Attachment{
			Metadata:   VA.GetMetadata(),
			InstanceId: instanceidVAl,
		})

	}

	if kmsKeyAttr.IsResourceBlockReference("aws_kms_key") {
		if kmsKeyBlock, err := module.GetReferencedBlock(kmsKeyAttr, resource); err == nil {
			kmsKeyVal = types.String(kmsKeyBlock.FullName(), kmsKeyBlock.GetMetadata())
		}
	}
	var ebsDefaultEncryp types.BoolValue
	for _, res := range module.GetResourcesByType("aws_ebs_encryption_by_default") {
		ebsDefaultEncryp = res.GetAttribute("enabled").AsBoolValueOrDefault(true, res)
	}

	var ebsDefaultkmskeyid types.StringValue
	for _, res := range module.GetResourcesByType("aws_ebs_default_kms_key") {
		ebsDefaultkmskeyid = res.GetAttribute("key_arn").AsStringValueOrDefault("", res)
	}

	return ec2.Volume{
		Metadata:    resource.GetMetadata(),
		VolumeId:    idVal,
		Attachments: attachement,
		Encryption: ec2.Encryption{
			Metadata: resource.GetMetadata(),
			Enabled:  encryptedVal,
			KMSKeyID: kmsKeyVal,
		},
		EbsEncryptionByDefault: ebsDefaultEncryp,
		EbsDefaultKmsKeyId:     ebsDefaultkmskeyid,
		Tags:                   gettags(resource),
	}
}

func adaptSnapShot(resource *terraform.Block, module *terraform.Module) ec2.Snapshot {

	var CVP []ec2.CreateVolumePermission
	CVPres := module.GetReferencingResources(resource, "aws_snapshot_create_volume_permission", "snapshot_id")
	for _, r := range CVPres {
		CVP = append(CVP, ec2.CreateVolumePermission{
			Metadata: r.GetMetadata(),
		})
	}

	return ec2.Snapshot{
		Metadata:                resource.GetMetadata(),
		SnapshotId:              resource.GetAttribute("id").AsStringValueOrDefault("", resource),
		VolumeId:                resource.GetAttribute("volume_id").AsStringValueOrDefault("", resource),
		Ownerid:                 resource.GetAttribute("owner_id").AsStringValueOrDefault("", resource),
		Encrypted:               resource.GetAttribute("encrypted").AsBoolValueOrDefault(true, resource),
		Tags:                    gettags(resource),
		CreateVolumePermissions: CVP,
	}
}

func gettags(resource *terraform.Block) []ec2.Tags {
	var tags []ec2.Tags

	for _, r := range resource.GetBlocks("tags") {
		tags = append(tags, ec2.Tags{
			Metadata: r.GetMetadata(),
		})
	}
	return tags
}
