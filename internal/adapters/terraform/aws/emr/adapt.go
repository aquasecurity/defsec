package emr

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/emr"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
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

func adaptCluster(resource *terraform.Block) emr.Cluster {

	var ec2SubnetId types.StringValue
	if ec2block := resource.GetBlock("ec2_attributes"); ec2block.IsNotNil() {
		ec2SubnetId = ec2block.GetAttribute("subnet_id").AsStringValueOrDefault("", resource)
	}

	return emr.Cluster{
		Metadata:      resource.GetMetadata(),
		EC2SubnetId:   ec2SubnetId,
		LogUri:        resource.GetAttribute("log_uri").AsStringValueOrDefault("", resource),
		InstanceGroup: getInstanceGroup(resource),
	}

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

func adaptSecurityConfiguration(resource *terraform.Block) emr.SecurityConfiguration {

	return emr.SecurityConfiguration{
		Metadata:      resource.GetMetadata(),
		Name:          resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		Configuration: resource.GetAttribute("configuration").AsStringValueOrDefault("", resource),
	}

}

func getInstanceGroup(resource *terraform.Block) emr.InstanceGroup {
	var masterinstance emr.Instance
	var coreinstance emr.Instance

	if mastergroupBlock := resource.GetBlock("master_instance_group"); mastergroupBlock.IsNotNil() {
		masterinstance = emr.Instance{
			Metadata:      mastergroupBlock.GetMetadata(),
			InstanceType:  mastergroupBlock.GetAttribute("instance_type").AsStringValueOrDefault("", mastergroupBlock),
			InstanceCount: mastergroupBlock.GetAttribute("instance_count").AsIntValueOrDefault(1, mastergroupBlock),
		}
	}

	if coregroupBlock := resource.GetBlock("core_instance_group"); coregroupBlock.IsNotNil() {
		coreinstance = emr.Instance{
			Metadata:      coregroupBlock.GetMetadata(),
			InstanceType:  coregroupBlock.GetAttribute("instance_type").AsStringValueOrDefault("", coregroupBlock),
			InstanceCount: coregroupBlock.GetAttribute("instance_count").AsIntValueOrDefault(1, coregroupBlock),
		}
	}
	return emr.InstanceGroup{
		Metadata:            resource.GetMetadata(),
		MasterInstanceGroup: masterinstance,
		CoreInstanceGroup:   coreinstance,
	}
}
