package emr

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/emr"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getClusters(ctx parser.FileContext) (clusters []emr.Cluster) {
	clusterResources := ctx.GetResourcesByType("AWS::EMR::Cluster")

	for _, r := range clusterResources {
		cluster := emr.Cluster{
			Metadata:    r.Metadata(),
			EC2SubnetId: r.GetStringProperty("Ec2SubnetId"),
			LogUri:      r.GetStringProperty("LogUri"),
			InstanceGroup: emr.InstanceGroup{
				Metadata: r.Metadata(),
				MasterInstanceGroup: emr.Instance{
					Metadata:      r.Metadata(),
					InstanceType:  r.GetStringProperty("Instances.MasterInstanceGroup.InstanceType"),
					InstanceCount: r.GetIntProperty("Instances.MasterInstanceGroup.InstanceCount"),
				},
				CoreInstanceGroup: emr.Instance{
					Metadata:      r.Metadata(),
					InstanceType:  r.GetStringProperty("Instances.CoreInstanceGroup.InstanceType"),
					InstanceCount: r.GetIntProperty("Instances.CoreInstanceGroup.InstanceCount"),
				},
			},
		}
		clusters = append(clusters, cluster)
	}
	return clusters
}

func getSecurityConfigurations(ctx parser.FileContext) []emr.SecurityConfiguration {

	resources := ctx.GetResourcesByType("AWS::EMR::SecurityConfiguration")
	var SC []emr.SecurityConfiguration
	for _, r := range resources {
		SC = append(SC, emr.SecurityConfiguration{
			Metadata:      r.Metadata(),
			Name:          r.GetStringProperty("Name"),
			Configuration: r.GetStringProperty("SecurityConfiguration"),
		})
	}
	return SC
}
