package rds

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getClustersAndInstances(ctx parser.FileContext) (clusters []rds.Cluster, orphans []rds.Instance) {

	clusterMap := getClusters(ctx)

	for _, r := range ctx.GetResourcesByType("AWS::RDS::DBInstance") {

		instance := rds.Instance{
			Metadata:                  r.Metadata(),
			BackupRetentionPeriodDays: r.GetIntProperty("BackupRetentionPeriod", 1),
			ReplicationSourceARN:      r.GetStringProperty("SourceDBInstanceIdentifier"),
			PerformanceInsights: rds.PerformanceInsights{
				Metadata: r.Metadata(),
				Enabled:  r.GetBoolProperty("EnablePerformanceInsights"),
				KMSKeyID: r.GetStringProperty("PerformanceInsightsKMSKeyId"),
			},
			Encryption: rds.Encryption{
				Metadata:       r.Metadata(),
				EncryptStorage: r.GetBoolProperty("StorageEncrypted"),
				KMSKeyID:       r.GetStringProperty("KmsKeyId"),
			},
			PublicAccess:                     r.GetBoolProperty("PubliclyAccessible", true),
			Engine:                           r.GetStringProperty("Engine"),
			IAMAuthEnabled:                   r.GetBoolProperty("EnableIAMDatabaseAuthentication"),
			DeletionProtection:               r.GetBoolProperty("DeletionProtection", false),
			DBInstanceArn:                    r.GetStringProperty("DBInstanceArn"),
			StorageEncrypted:                 r.GetBoolProperty("StorageEncrypted", false),
			DBInstanceIdentifier:             r.GetStringProperty("DBInstanceIdentifier"),
			DBParameterGroups:                getDBParameterGroups(r),
			TagList:                          getTagList(r),
			EnabledCloudwatchLogsExports:     getEnabledCloudwatchLogsExports(r),
			EngineVersion:                    r.GetStringProperty("EngineVersion"),
			AutoMinorVersionUpgrade:          r.GetBoolProperty("AutoMinorVersionUpgrade"),
			MultiAZ:                          r.GetBoolProperty("MultiAZ"),
			PubliclyAccessible:               r.GetBoolProperty("PubliclyAccessible"),
			LatestRestorableTime:             types.TimeUnresolvable(r.Metadata()),
			ReadReplicaDBInstanceIdentifiers: getReadReplicaDBInstanceIdentifiers(r),
		}

		if clusterID := r.GetProperty("DBClusterIdentifier"); clusterID.IsString() {
			var found bool
			for key, cluster := range clusterMap {
				if key == clusterID.AsString() {
					cluster.Instances = append(cluster.Instances, rds.ClusterInstance{
						Instance:          instance,
						ClusterIdentifier: clusterID.AsStringValue(),
					})
					clusterMap[key] = cluster
					found = true
					break
				}
			}
			if found {
				continue
			}
		}

		orphans = append(orphans, instance)
	}

	for _, cluster := range clusterMap {
		clusters = append(clusters, cluster)
	}

	return clusters, orphans
}

func getDBParameterGroups(r *parser.Resource) (dbpmgroup []rds.DBParameterGroupsList) {

	DBParameterGroup := r.GetProperty("DBParameterGroups")

	if DBParameterGroup.IsNil() || DBParameterGroup.IsNotNil() {
		return dbpmgroup
	}

	for _, DBPMG := range DBParameterGroup.AsList() {
		dbpmgroup = append(dbpmgroup, rds.DBParameterGroupsList{
			Metadata:             DBPMG.Metadata(),
			DBParameterGroupName: DBPMG.AsStringValue(),
			KMSKeyID:             DBPMG.AsStringValue(),
		})
	}
	return dbpmgroup
}

func getEnabledCloudwatchLogsExports(r *parser.Resource) (enabledcloudwatchlogexportslist []types.StringValue) {
	enabledCloudwatchLogExportList := r.GetProperty("EnableCloudwatchLogsExports")

	if enabledCloudwatchLogExportList.IsNil() || enabledCloudwatchLogExportList.IsNotNil() {
		return enabledcloudwatchlogexportslist
	}

	for _, ECLE := range enabledCloudwatchLogExportList.AsList() {
		enabledcloudwatchlogexportslist = append(enabledcloudwatchlogexportslist, ECLE.AsStringValue())
	}
	return enabledcloudwatchlogexportslist
}

func getTagList(r *parser.Resource) (taglist []rds.TagList) {
	TagLists := r.GetProperty("tags")

	if TagLists.IsNil() || TagLists.IsNotNil() {
		return taglist
	}

	for _, TL := range TagLists.AsList() {
		taglist = append(taglist, rds.TagList{
			Metadata: TL.Metadata(),
		})
	}
	return taglist
}

func getReadReplicaDBInstanceIdentifiers(r *parser.Resource) (readreplicadbidentifier []types.StringValue) {
	ReadReplicaDBIdentifier := r.GetProperty("EnableCloudwatchLogsExports")

	if ReadReplicaDBIdentifier.IsNil() || ReadReplicaDBIdentifier.IsNotNil() {
		return readreplicadbidentifier
	}

	for _, RR := range ReadReplicaDBIdentifier.AsList() {
		readreplicadbidentifier = append(readreplicadbidentifier, RR.AsStringValue())
	}
	return readreplicadbidentifier
}
