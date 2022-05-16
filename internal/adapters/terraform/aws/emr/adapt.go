package emr

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/emr"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) emr.EMR {
	return emr.EMR{
		Clusters:              adaptClusters(modules),
		SecurityConfiguration: adaptSecurityConfigurations(modules),
	}
}
func adaptClusters(modules terraform.Modules) []emr.Cluster {
	var clusters []emr.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_emr_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptSecurityConfigurations(modules terraform.Modules) []emr.SecurityConfiguration {
	var securityConfiguration []emr.SecurityConfiguration
	// fmt.Print(securityConfiguration)
	// return securityConfiguration
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elasticache_replication_group") {
			securityConfiguration = append(securityConfiguration, adaptSecurityConfiguration(resource))
		}
	}
	return securityConfiguration
}

func adaptCluster(resource *terraform.Block) emr.Cluster {

	return emr.Cluster{
		Metadata: resource.GetMetadata(),
	}
}

func adaptSecurityConfiguration(resource *terraform.Block) emr.SecurityConfiguration {
	enableInTransitEncryptionAttr := resource.GetAttribute("EnableInTransitEncryption")
	enableInTransitEncryptionVal := enableInTransitEncryptionAttr.AsBoolValueOrDefault(false, resource)

	encryptionAtRestEnabledAttr := resource.GetAttribute("EnableAtRestEncryption")
	encryptionAtRestEnabledVal := encryptionAtRestEnabledAttr.AsBoolValueOrDefault(false, resource)

	configurationAttr := resource.GetAttribute("configuration")
	configurationVal := configurationAttr.AsStringValueOrDefault("", resource)

	// Configuration := resource.GetAttribute("configuration").AsStringValueOrDefault("", resource)

}

// func adaptTaskDefinitionResource(resourceBlock *terraform.Block) ecs.TaskDefinition {
// 	return ecs.TaskDefinition{
// 		Metadata:             resourceBlock.GetMetadata(),
// 		Volumes:              adaptVolumes(resourceBlock),
// 		ContainerDefinitions: resourceBlock.GetAttribute("container_definitions").AsStringValueOrDefault("", resourceBlock),
// 	}
// }
