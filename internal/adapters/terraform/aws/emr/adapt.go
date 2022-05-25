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
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_emr_security_configuration") {
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
	configurationAttr := resource.GetAttribute("configuration")
	configurationVal := configurationAttr.AsStringValueOrDefault("", resource)

	return emr.SecurityConfiguration{
		Configuration: configurationVal,
	}

}
