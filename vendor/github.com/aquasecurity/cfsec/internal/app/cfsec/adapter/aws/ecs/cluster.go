package ecs

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/ecs"
	"github.com/aquasecurity/defsec/types"
)

func getClusters(ctx parser.FileContext) (clusters []ecs.Cluster) {

	clusterResources := ctx.GetResourceByType("AWS::ECS::Cluster")

	for _, r := range clusterResources {

		cluster := ecs.Cluster{
			Metadata: r.Metadata(),
			Settings: getClusterSettings(r),
		}

		clusters = append(clusters, cluster)

	}

	return clusters
}

func getClusterSettings(r *parser.Resource) (clusterSettings ecs.ClusterSettings) {

	clusterSettings.ContainerInsightsEnabled = types.BoolDefault(false, r.Metadata())

	clusterSettingMap := r.GetProperty("ClusterSettings")
	if clusterSettingMap.IsNil() || clusterSettingMap.IsNotList() {
		return clusterSettings
	}

	for _, setting := range clusterSettingMap.AsList() {
		checkProperty(setting, &clusterSettings)
	}

	return clusterSettings
}

func checkProperty(setting *parser.Property, clusterSettings *ecs.ClusterSettings) {
	settingMap := setting.AsMap()
	name := settingMap["Name"]
	if name.IsNotNil() && name.EqualTo("containerInsights") {
		value := settingMap["Value"]
		if value.IsNotNil() && value.EqualTo("enabled") {
			clusterSettings.ContainerInsightsEnabled = types.Bool(true, value.Metadata())
		}
	}
}
