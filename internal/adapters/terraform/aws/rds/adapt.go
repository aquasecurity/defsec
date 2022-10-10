package rds

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) rds.RDS {
	return rds.RDS{
		Instances: getInstances(modules),
		Clusters:  getClusters(modules),
		Classic:   getClassic(modules),
	}
}

func getInstances(modules terraform.Modules) (instances []rds.Instance) {
	for _, resource := range modules.GetResourcesByType("aws_db_instance") {
		instances = append(instances, adaptInstance(resource, modules))
	}

	return instances
}

func getClusters(modules terraform.Modules) (clusters []rds.Cluster) {

	rdsInstanceMaps := modules.GetChildResourceIDMapByType("aws_rds_cluster_instance")
	for _, resource := range modules.GetResourcesByType("aws_rds_cluster") {
		cluster, instanceIDs := adaptCluster(resource, modules)
		for _, id := range instanceIDs {
			rdsInstanceMaps.Resolve(id)
		}
		clusters = append(clusters, cluster)
	}

	orphanResources := modules.GetResourceByIDs(rdsInstanceMaps.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := rds.Cluster{
			Metadata:                  defsecTypes.NewUnmanagedMetadata(),
			BackupRetentionPeriodDays: defsecTypes.IntDefault(1, defsecTypes.NewUnmanagedMetadata()),
			ReplicationSourceARN:      defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
			PerformanceInsights: rds.PerformanceInsights{
				Metadata: defsecTypes.NewUnmanagedMetadata(),
				Enabled:  defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
				KMSKeyID: defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
			},
			Instances: nil,
			Encryption: rds.Encryption{
				Metadata:       defsecTypes.NewUnmanagedMetadata(),
				EncryptStorage: defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
				KMSKeyID:       defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
			},
			PublicAccess: defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
			Engine:       defsecTypes.StringUnresolvable(defsecTypes.NewUnmanagedMetadata()),
		}
		for _, orphan := range orphanResources {
			orphanage.Instances = append(orphanage.Instances, adaptClusterInstance(orphan, modules))
		}
		clusters = append(clusters, orphanage)
	}

	return clusters
}

func getClassic(modules terraform.Modules) rds.Classic {
	classic := rds.Classic{
		DBSecurityGroups: nil,
	}
	for _, resource := range modules.GetResourcesByType("aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group") {
		classic.DBSecurityGroups = append(classic.DBSecurityGroups, adaptClassicDBSecurityGroup(resource))
	}
	return classic
}

func adaptClusterInstance(resource *terraform.Block, modules terraform.Modules) rds.ClusterInstance {
	clusterIdAttr := resource.GetAttribute("cluster_identifier")
	clusterId := clusterIdAttr.AsStringValueOrDefault("", resource)

	if clusterIdAttr.IsResourceBlockReference("aws_rds_cluster") {
		if referenced, err := modules.GetReferencedBlock(clusterIdAttr, resource); err == nil {
			clusterId = defsecTypes.String(referenced.FullName(), referenced.GetMetadata())
		}
	}

	return rds.ClusterInstance{
		ClusterIdentifier: clusterId,
		Instance:          adaptInstance(resource, modules),
	}
}

func adaptClassicDBSecurityGroup(resource *terraform.Block) rds.DBSecurityGroup {
	return rds.DBSecurityGroup{
		Metadata: resource.GetMetadata(),
	}
}

func adaptInstance(resource *terraform.Block, modules terraform.Modules) rds.Instance {
	replicaSource := resource.GetAttribute("replicate_source_db")
	replicaSourceValue := ""
	if replicaSource.IsNotNil() {
		if referenced, err := modules.GetReferencedBlock(replicaSource, resource); err == nil {
			replicaSourceValue = referenced.ID()
		}
	}
	return rds.Instance{
		Metadata:                  resource.GetMetadata(),
		BackupRetentionPeriodDays: resource.GetAttribute("backup_retention_period").AsIntValueOrDefault(0, resource),
		ReplicationSourceARN:      defsecTypes.StringExplicit(replicaSourceValue, resource.GetMetadata()),
		PerformanceInsights:       adaptPerformanceInsights(resource),
		Encryption:                adaptEncryption(resource),
		PublicAccess:              resource.GetAttribute("publicly_accessible").AsBoolValueOrDefault(false, resource),
		Engine:                    resource.GetAttribute("engine").AsStringValueOrDefault(rds.EngineAurora, resource),
		IAMAuthEnabled:            resource.GetAttribute("iam_database_authentication_enabled").AsBoolValueOrDefault(false, resource),
		DeletionProtection:        resource.GetAttribute("deletion_protection").AsBoolValueOrDefault(false, resource),
	}
}

func adaptCluster(resource *terraform.Block, modules terraform.Modules) (rds.Cluster, []string) {

	clusterInstances, ids := getClusterInstances(resource, modules)

	var public bool
	for _, instance := range clusterInstances {
		if instance.PublicAccess.IsTrue() {
			public = true
			break
		}
	}

	return rds.Cluster{
		Metadata:                  resource.GetMetadata(),
		BackupRetentionPeriodDays: resource.GetAttribute("backup_retention_period").AsIntValueOrDefault(1, resource),
		ReplicationSourceARN:      resource.GetAttribute("replication_source_identifier").AsStringValueOrDefault("", resource),
		PerformanceInsights:       adaptPerformanceInsights(resource),
		Instances:                 clusterInstances,
		Encryption:                adaptEncryption(resource),
		PublicAccess:              defsecTypes.Bool(public, resource.GetMetadata()),
		Engine:                    resource.GetAttribute("engine").AsStringValueOrDefault(rds.EngineAurora, resource),
	}, ids
}

func getClusterInstances(resource *terraform.Block, modules terraform.Modules) (clusterInstances []rds.ClusterInstance, instanceIDs []string) {
	clusterInstanceResources := modules.GetReferencingResources(resource, "aws_rds_cluster_instance", "cluster_identifier")

	for _, ciResource := range clusterInstanceResources {
		instanceIDs = append(instanceIDs, ciResource.ID())
		clusterInstances = append(clusterInstances, adaptClusterInstance(ciResource, modules))
	}
	return clusterInstances, instanceIDs
}

func adaptPerformanceInsights(resource *terraform.Block) rds.PerformanceInsights {
	return rds.PerformanceInsights{
		Metadata: resource.GetMetadata(),
		Enabled:  resource.GetAttribute("performance_insights_enabled").AsBoolValueOrDefault(false, resource),
		KMSKeyID: resource.GetAttribute("performance_insights_kms_key_id").AsStringValueOrDefault("", resource),
	}
}

func adaptEncryption(resource *terraform.Block) rds.Encryption {
	return rds.Encryption{
		Metadata:       resource.GetMetadata(),
		EncryptStorage: resource.GetAttribute("storage_encrypted").AsBoolValueOrDefault(false, resource),
		KMSKeyID:       resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
	}
}
