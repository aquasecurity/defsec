package rds

import (
	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws"
	rdsApi "github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type adapter struct {
	*aws2.RootAdapter
	api *rdsApi.Client
}

func init() {
	aws2.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Name() string {
	return "rds"
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Adapt(root *aws2.RootAdapter, state *state.State) error {

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

func (a *adapter) getInstances() (instances []rds.Instance, err error) {

	a.Tracker().SetServiceLabel("Discovering RDS instances...")
	var apiDBInstances []types.DBInstance
	var input rdsApi.DescribeDBInstancesInput

	for {
		output, err := a.api.DescribeDBInstances(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiDBInstances = append(apiDBInstances, output.DBInstances...)
		a.Tracker().SetTotalResources(len(apiDBInstances))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting RDS instances...")
	return concurrency.Adapt(apiDBInstances, a.RootAdapter, a.adaptDBInstance), nil
}

func (a *adapter) getClusters() (clusters []rds.Cluster, err error) {

	a.Tracker().SetServiceLabel("Discovering RDS clusters...")
	var apDBClusters []types.DBCluster
	var input rdsApi.DescribeDBClustersInput

	for {
		output, err := a.api.DescribeDBClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apDBClusters = append(apDBClusters, output.DBClusters...)
		a.Tracker().SetTotalResources(len(apDBClusters))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}
	a.Tracker().SetServiceLabel("Adapting RDS clusters...")
	return concurrency.Adapt(apDBClusters, a.RootAdapter, a.adaptCluster), nil
}

func (a *adapter) getClassic() (rds.Classic, error) {

	classic := rds.Classic{
		DBSecurityGroups: nil,
	}

	a.Tracker().SetServiceLabel("Discovering RDS classic instances...")
	var apiDBSGs []types.DBSecurityGroup
	var input rdsApi.DescribeDBSecurityGroupsInput

	for {
		output, err := a.api.DescribeDBSecurityGroups(a.Context(), &input)
		if err != nil {
			return classic, err
		}
		apiDBSGs = append(apiDBSGs, output.DBSecurityGroups...)
		a.Tracker().SetTotalResources(len(apiDBSGs))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}
	a.Tracker().SetServiceLabel("Adapting RDS clusters...")
	sgs := concurrency.Adapt(apiDBSGs, a.RootAdapter, a.adaptClassic)

	classic.DBSecurityGroups = sgs
	return classic, nil
}

func (a *adapter) adaptDBInstance(dbInstance types.DBInstance) (*rds.Instance, error) {

	dbInstanceMetadata := a.CreateMetadata("db:" + *dbInstance.DBInstanceIdentifier)

	engine := rds.EngineAurora
	if dbInstance.Engine != nil {
		engine = *dbInstance.Engine
	}

	instance := &rds.Instance{
		Metadata:                  dbInstanceMetadata,
		BackupRetentionPeriodDays: defsecTypes.IntFromInt32(dbInstance.BackupRetentionPeriod, dbInstanceMetadata),
		ReplicationSourceARN:      defsecTypes.String(aws.ToString(dbInstance.ReadReplicaSourceDBInstanceIdentifier), dbInstanceMetadata),
		PerformanceInsights: getPerformanceInsights(
			dbInstance.PerformanceInsightsEnabled,
			dbInstance.PerformanceInsightsKMSKeyId,
			dbInstanceMetadata,
		),
		Encryption:     getInstanceEncryption(dbInstance.StorageEncrypted, dbInstance.KmsKeyId, dbInstanceMetadata),
		PublicAccess:   defsecTypes.Bool(dbInstance.PubliclyAccessible, dbInstanceMetadata),
		Engine:         defsecTypes.String(engine, dbInstanceMetadata),
		IAMAuthEnabled: defsecTypes.Bool(dbInstance.IAMDatabaseAuthenticationEnabled, dbInstanceMetadata),
	}

	return instance, nil
}

func (a *adapter) adaptCluster(dbCluster types.DBCluster) (*rds.Cluster, error) {

	dbClusterMetadata := a.CreateMetadata("cluster:" + *dbCluster.DBClusterIdentifier)

	engine := rds.EngineAurora
	if dbCluster.Engine != nil {
		engine = *dbCluster.Engine
	}

	cluster := &rds.Cluster{
		Metadata:                  dbClusterMetadata,
		BackupRetentionPeriodDays: defsecTypes.IntFromInt32(aws.ToInt32(dbCluster.BackupRetentionPeriod), dbClusterMetadata),
		ReplicationSourceARN:      defsecTypes.String(aws.ToString(dbCluster.ReplicationSourceIdentifier), dbClusterMetadata),
		PerformanceInsights: getPerformanceInsights(
			dbCluster.PerformanceInsightsEnabled,
			dbCluster.PerformanceInsightsKMSKeyId,
			dbClusterMetadata,
		),
		Encryption:   getInstanceEncryption(dbCluster.StorageEncrypted, dbCluster.KmsKeyId, dbClusterMetadata),
		PublicAccess: defsecTypes.Bool(aws.ToBool(dbCluster.PubliclyAccessible), dbClusterMetadata),
		Engine:       defsecTypes.String(engine, dbClusterMetadata),
	}

	return cluster, nil
}

func (a *adapter) adaptClassic(dbSecurityGroup types.DBSecurityGroup) (*rds.DBSecurityGroup, error) {

	dbSecurityGroupMetadata := a.CreateMetadata("secgrp:" + *dbSecurityGroup.DBSecurityGroupName)

	dbsg := &rds.DBSecurityGroup{
		Metadata: dbSecurityGroupMetadata,
	}

	return dbsg, nil
}

func getInstanceEncryption(storageEncrypted bool, kmsKeyID *string, metadata defsecTypes.Metadata) rds.Encryption {
	encryption := rds.Encryption{
		Metadata:       metadata,
		EncryptStorage: defsecTypes.BoolDefault(storageEncrypted, metadata),
		KMSKeyID:       defsecTypes.StringDefault("", metadata),
	}

	if kmsKeyID != nil {
		encryption.KMSKeyID = defsecTypes.String(*kmsKeyID, metadata)
	}

	return encryption
}

func getPerformanceInsights(enabled *bool, kmsKeyID *string, metadata defsecTypes.Metadata) rds.PerformanceInsights {
	performanceInsights := rds.PerformanceInsights{
		Metadata: metadata,
		Enabled:  defsecTypes.BoolDefault(false, metadata),
		KMSKeyID: defsecTypes.StringDefault("", metadata),
	}
	if enabled != nil {
		performanceInsights.Enabled = defsecTypes.Bool(*enabled, metadata)
	}
	if kmsKeyID != nil {
		performanceInsights.KMSKeyID = defsecTypes.String(*kmsKeyID, metadata)
	}

	return performanceInsights
}
