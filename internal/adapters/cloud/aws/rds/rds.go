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

	state.AWS.RDS.Snapshots, err = a.getSnapshots()
	if err != nil {
		return err
	}

	state.AWS.RDS.Parameters, err = a.getParameters()
	if err != nil {
		return err
	}

	state.AWS.RDS.SnapshotAttributes, err = a.getSnapshotAttributes()
	if err != nil {
		return err
	}

	state.AWS.RDS.ParameterGroups, err = a.getParameterGroups()
	if err != nil {
		return err
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

func (a *adapter) getParameter() (parameter []rds.Parameter, err error) {
	a. Tracker().SetServiceLabel(" Parameter...")
	var apiParameter []types.DBParameterGroup
	var input rdsApi.DescribeDBParameterGroupsInput

	for {
		output, err := a.api.DescribeDBParameters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiParameter = append(apiParameter, output.Parameters...)
		a.Tracker().SetTotalResources(len(apiParameter))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

		a.Tracker().SetServiceLabel("Adapting RDS Parameters Groups")
		return concurrency.Adapt(apiParameter, a.RootAdapter, a.adaptParameter), nil
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

	// EnabledCloudwatchLogsExport := defsecTypes.StringValueList()
	// if dbInstance.EnabledCloudwatchLogsExports != nil {
	// 	EnabledCloudwatchLogsExport = defsecTypes.StringValueList(dbInstance.EnabledCloudwatchLogsExports, metadata)
	// }

	instance := &rds.Instance{
		Metadata:                  dbInstanceMetadata,
		BackupRetentionPeriodDays: defsecTypes.IntFromInt32(dbInstance.BackupRetentionPeriod, dbInstanceMetadata),
		ReplicationSourceARN:      defsecTypes.String(aws.ToString(dbInstance.ReadReplicaSourceDBInstanceIdentifier), dbInstanceMetadata),
		PerformanceInsights: getPerformanceInsights(
			dbInstance.PerformanceInsightsEnabled,
			dbInstance.PerformanceInsightsKMSKeyId,
			dbInstanceMetadata,
		),
		Encryption:                       getInstanceEncryption(dbInstance.StorageEncrypted, dbInstance.KmsKeyId, dbInstanceMetadata),
		PublicAccess:                     defsecTypes.Bool(dbInstance.PubliclyAccessible, dbInstanceMetadata),
		Engine:                           defsecTypes.String(engine, dbInstanceMetadata),
		IAMAuthEnabled:                   defsecTypes.Bool(dbInstance.IAMDatabaseAuthenticationEnabled, dbInstanceMetadata),
		DeletionProtection:               defsecTypes.Bool(dbInstance.DeletionProtection, dbInstanceMetadata),
		DBInstanceArn:                    defsecTypes.String(engine, dbInstanceMetadata),
		StorageEncrypted:                 defsecTypes.Bool(dbInstance.StorageEncrypted, dbInstanceMetadata),
		DBInstanceIdentifier:             defsecTypes.String(engine, dbInstanceMetadata),
		DBParameterGroups:                getDBParameterGroups(dbInstance.DBParameterGroups, dbinstance.KmsKeyId, dbInstanceMetadata),
		TagList:                          getTagList(dbInstance.TagList, dbinstance.KmsKeyId, dbInstanceMetadata),
		EnabledCloudwatchLogsExports:     defsecTypes.String(engine, dbInstanceMetadata),
		EngineVersion:                    defsecTypes.String(engine, dbInstanceMetadata),
		AutoMinorVersionUpgrade:          defsecTypes.Bool(dbInstance.AutoMinorVersionUpgrade, dbInstanceMetadata),
		MultiAZ:                          defsecTypes.Bool(dbInstance.MultiAZ, dbInstanceMetadata),
		PubliclyAccessible:               defsecTypes.Bool(dbInstance.PubliclyAccessible, dbInstanceMetadata),
		LatestRestorableTime:             defsecTypes.TimeValue(engine, dbInstanceMetadata),
		ReadReplicaDBInstanceIdentifiers: defsecTypes.StringValueList(engine, dbInstanceMetadata),
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
		LatestRestorableTime: defsecTypes.TimeValue{},
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

func (a *adapter) adaptParameter(dbparameter types.Parameter) (*rds.Parameters, error) {
	dbParameterMetedata := a.CreateMetadata("parametgrp" + *dbparameter.ParameterName)

	p
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

func getDBParameterGroups(dbParameterGroupName string, kmsKeyID *string, metadata defsecTypes.Metadata) rds.DBParameterGroupsList {
	dbParameterGroupList := rds.DBParameterGroupsList{
		Metadata:             metadata,
		DBParameterGroupName: defsecTypes.StringDefault("", metadata),
		KMSKeyID:             defsecTypes.StringDefault("", metadata),
	}
	if dbParameterGroupName != nil {
		dbParameterGroupList.DBParameterGroupName = defsecTypes.String(*dbParameterGroupName, metadata)
	}
	if kmsKeyID != nil {
		dbParameterGroupList.KMSKeyID = defsecTypes.String(*kmsKeyID, metadata)
	}

	return dbParameterGroupList
}
