package rds

import (
	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/state"
	types2 "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws"
	rdsApi "github.com/aws/aws-sdk-go-v2/service/rds"
)

type adapter struct {
	*aws2.RootAdapter
	api *rdsApi.Client
}

func init() {
	aws2.RegisterServiceAdapter(&adapter{})
}

func (a adapter) Name() string {
	return "rds"
}

func (a adapter) Provider() string {
	return "aws"
}

func (a adapter) Adapt(root *aws2.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = rdsApi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.RDS.Instances, err = a.getInstances()
	if err != nil {
		return err
	}

	state.AWS.RDS.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	state.AWS.RDS.Classic, err = a.getClassic()
	if err != nil {
		a.Debug("Failed to retrieve classic resource: %s", err)
		return nil
	}

	return nil
}

func (a adapter) getInstances() (instances []rds.Instance, err error) {

	a.Tracker().SetServiceLabel("Scanning RDS instances...")

	batchInstances, token, err := a.getInstanceBatch(nil)
	if err != nil {
		return instances, err
	}

	instances = append(instances, batchInstances...)

	for token != nil {
		instances, token, err = a.getInstanceBatch(token)
		if err != nil {
			return instances, err
		}
		instances = append(instances, batchInstances...)
	}

	return instances, nil
}

func (a adapter) getClusters() (clusters []rds.Cluster, err error) {

	a.Tracker().SetServiceLabel("Scanning RDS clusters...")

	batchClusters, token, err := a.getClusterBatch(nil)
	if err != nil {
		return clusters, err
	}

	clusters = append(clusters, batchClusters...)

	for token != nil {
		clusters, token, err = a.getClusterBatch(token)
		if err != nil {
			return clusters, err
		}
		clusters = append(clusters, batchClusters...)
	}

	return clusters, nil
}

func (a adapter) getClassic() (rds.Classic, error) {

	classic := rds.Classic{
		DBSecurityGroups: nil,
	}

	a.Tracker().SetServiceLabel("Scanning RDS classic instances...")

	classicSecurityGroups, token, err := a.getClassicBatch(nil)
	if err != nil {
		return classic, err
	}

	classic.DBSecurityGroups = append(classic.DBSecurityGroups, classicSecurityGroups...)

	for token != nil {
		classic.DBSecurityGroups, token, err = a.getClassicBatch(token)
		if err != nil {
			return classic, err
		}
		classic.DBSecurityGroups = append(classic.DBSecurityGroups, classicSecurityGroups...)
	}

	return classic, err
}

func (a *adapter) getInstanceBatch(token *string) (instances []rds.Instance, nextToken *string, err error) {

	input := &rdsApi.DescribeDBInstancesInput{}

	if token != nil {
		input.Marker = token
	}

	apiDbInstances, err := a.api.DescribeDBInstances(a.Context(), input)
	if err != nil {
		return instances, nextToken, err
	}

	for _, dbInstance := range apiDbInstances.DBInstances {

		dbInstanceMetadata := a.CreateMetadata(*dbInstance.DBInstanceIdentifier)

		instances = append(instances, rds.Instance{
			Metadata:                  dbInstanceMetadata,
			BackupRetentionPeriodDays: types2.IntFromInt32(dbInstance.BackupRetentionPeriod, dbInstanceMetadata),
			ReplicationSourceARN:      types2.String(aws.ToString(dbInstance.ReadReplicaSourceDBInstanceIdentifier), dbInstanceMetadata),
			PerformanceInsights: getPerformanceInsights(
				dbInstance.PerformanceInsightsEnabled,
				dbInstance.PerformanceInsightsKMSKeyId,
				dbInstanceMetadata,
			),
			Encryption:   getInstanceEncryption(dbInstance.StorageEncrypted, dbInstance.KmsKeyId, dbInstanceMetadata),
			PublicAccess: types2.Bool(dbInstance.PubliclyAccessible, dbInstanceMetadata),
		})

		a.Tracker().IncrementResource()
	}

	nextToken = apiDbInstances.Marker
	return instances, nextToken, nil
}

func (a *adapter) getClusterBatch(token *string) (clusters []rds.Cluster, nextToken *string, err error) {

	input := &rdsApi.DescribeDBClustersInput{}
	if token != nil {
		input.Marker = token
	}

	apiDbClusters, err := a.api.DescribeDBClusters(a.Context(), input)
	if err != nil {
		return clusters, nextToken, err
	}

	for _, dbCluster := range apiDbClusters.DBClusters {

		dbClusterMetadata := a.CreateMetadata(*dbCluster.DBClusterIdentifier)

		clusters = append(clusters, rds.Cluster{
			Metadata:                  dbClusterMetadata,
			BackupRetentionPeriodDays: types2.IntFromInt32(aws.ToInt32(dbCluster.BackupRetentionPeriod), dbClusterMetadata),
			ReplicationSourceARN:      types2.String(aws.ToString(dbCluster.ReplicationSourceIdentifier), dbClusterMetadata),
			PerformanceInsights: getPerformanceInsights(
				dbCluster.PerformanceInsightsEnabled,
				dbCluster.PerformanceInsightsKMSKeyId,
				dbClusterMetadata,
			),
			Encryption:   getInstanceEncryption(dbCluster.StorageEncrypted, dbCluster.KmsKeyId, dbClusterMetadata),
			PublicAccess: types2.Bool(aws.ToBool(dbCluster.PubliclyAccessible), dbClusterMetadata),
		})

	}
	nextToken = apiDbClusters.Marker
	return clusters, nextToken, nil
}

func (a *adapter) getClassicBatch(token *string) (dbSecurityGroups []rds.DBSecurityGroup, nextToken *string, err error) {

	input := &rdsApi.DescribeDBSecurityGroupsInput{}

	if token != nil {
		input.Marker = token
	}

	apiDbSecurityGroups, err := a.api.DescribeDBSecurityGroups(a.Context(), input)
	if err != nil {
		return dbSecurityGroups, nextToken, err
	}

	for _, dbSecurityGroup := range apiDbSecurityGroups.DBSecurityGroups {

		dbSecurityGroupMetadata := a.CreateMetadata(*dbSecurityGroup.DBSecurityGroupName)

		dbSecurityGroups = append(dbSecurityGroups, rds.DBSecurityGroup{
			Metadata: dbSecurityGroupMetadata,
		})

		a.Tracker().IncrementResource()
	}

	return dbSecurityGroups, nextToken, nil
}

func getInstanceEncryption(storageEncrypted bool, kmsKeyID *string, metadata types2.Metadata) rds.Encryption {
	encryption := rds.Encryption{
		Metadata:       metadata,
		EncryptStorage: types2.BoolDefault(storageEncrypted, metadata),
		KMSKeyID:       types2.StringDefault("", metadata),
	}

	if kmsKeyID != nil {
		encryption.KMSKeyID = types2.String(*kmsKeyID, metadata)
	}

	return encryption
}

func getPerformanceInsights(enabled *bool, kmsKeyID *string, metadata types2.Metadata) rds.PerformanceInsights {
	performanceInsights := rds.PerformanceInsights{
		Metadata: metadata,
		Enabled:  types2.BoolDefault(false, metadata),
		KMSKeyID: types2.StringDefault("", metadata),
	}

	if enabled != nil {
		performanceInsights.Enabled = types2.Bool(*enabled, metadata)
	}
	if kmsKeyID != nil {
		performanceInsights.KMSKeyID = types2.String(*kmsKeyID, metadata)
	}

	return performanceInsights
}
