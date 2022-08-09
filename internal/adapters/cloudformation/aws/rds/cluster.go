package rds

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

func getClusters(ctx parser.FileContext) (clusters map[string]rds.Cluster) {
	clusters = make(map[string]rds.Cluster)
	for _, clusterResource := range ctx.GetResourcesByType("AWS::RDS::DBCluster") {
		cluster := rds.Cluster{
			Metadata:                  clusterResource.Metadata(),
			BackupRetentionPeriodDays: types2.IntDefault(1, clusterResource.Metadata()),
			ReplicationSourceARN:      types2.StringDefault("", clusterResource.Metadata()),
			PerformanceInsights: rds.PerformanceInsights{
				Metadata: clusterResource.Metadata(),
				Enabled:  types2.BoolDefault(false, clusterResource.Metadata()),
				KMSKeyID: types2.StringDefault("", clusterResource.Metadata()),
			},
			Instances: nil,
			Encryption: rds.Encryption{
				Metadata:       clusterResource.Metadata(),
				EncryptStorage: types2.BoolDefault(false, clusterResource.Metadata()),
				KMSKeyID:       types2.StringDefault("", clusterResource.Metadata()),
			},
			PublicAccess: types2.BoolDefault(false, clusterResource.Metadata()),
		}

		if backupProp := clusterResource.GetProperty("BackupRetentionPeriod"); backupProp.IsInt() {
			cluster.BackupRetentionPeriodDays = backupProp.AsIntValue()
		}

		if replicaProp := clusterResource.GetProperty("SourceDBInstanceIdentifier"); replicaProp.IsString() {
			cluster.ReplicationSourceARN = replicaProp.AsStringValue()
		}

		if piProp := clusterResource.GetProperty("EnablePerformanceInsights"); piProp.IsBool() {
			cluster.PerformanceInsights.Enabled = piProp.AsBoolValue()
		}

		if insightsKeyProp := clusterResource.GetProperty("PerformanceInsightsKMSKeyId"); insightsKeyProp.IsString() {
			cluster.PerformanceInsights.KMSKeyID = insightsKeyProp.AsStringValue()
		}

		if encryptedProp := clusterResource.GetProperty("StorageEncrypted"); encryptedProp.IsBool() {
			cluster.Encryption.EncryptStorage = encryptedProp.AsBoolValue()
		}

		if keyProp := clusterResource.GetProperty("KmsKeyId"); keyProp.IsString() {
			cluster.Encryption.KMSKeyID = keyProp.AsStringValue()
		}

		clusters[clusterResource.ID()] = cluster
	}
	return clusters
}

func getClassic(ctx parser.FileContext) rds.Classic {
	return rds.Classic{
		DBSecurityGroups: getClassicSecurityGroups(ctx),
	}
}

func getClassicSecurityGroups(ctx parser.FileContext) (groups []rds.DBSecurityGroup) {
	for _, dbsgResource := range ctx.GetResourcesByType("AWS::RDS::DBSecurityGroup") {
		group := rds.DBSecurityGroup{
			Metadata: dbsgResource.Metadata(),
		}
		groups = append(groups, group)
	}
	return groups
}
