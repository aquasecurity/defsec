package dms

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/dms"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) dms.DMS {
	return dms.DMS{
		ReplicationInstances: getReplicationInstances(modules),
	}
}

func getReplicationInstances(modules terraform.Modules) []dms.ReplicationInstance {
	var replicationInstances []dms.ReplicationInstance
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_dms_replication_instance") {
			replicationInstances = append(replicationInstances, adaptReplicationInstance(resource))
		}
	}
	return replicationInstances
}

func adaptReplicationInstance(resource *terraform.Block) dms.ReplicationInstance {
	multiAZAttr := resource.GetAttribute("multi_az")
	multiAZVal := multiAZAttr.AsBoolValueOrDefault(true, resource)

	autoMinorUpgrateAttr := resource.GetAttribute("auto_minor_version_upgrade")
	autoMinorUpgrateVal := autoMinorUpgrateAttr.AsBoolValueOrDefault(false, resource)

	publiclyAccessibleAttr := resource.GetAttribute("publicly_accessible")
	publiclyAccessibleVal := publiclyAccessibleAttr.AsBoolValueOrDefault(false, resource)

	return dms.ReplicationInstance{
		Metadata:                resource.GetMetadata(),
		AutoMinorVersionUpgrade: autoMinorUpgrateVal,
		PubliclyAccessible:      publiclyAccessibleVal,
		MultiAZ:                 multiAZVal,
	}
}
