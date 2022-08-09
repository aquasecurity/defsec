package gke

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type GKE struct {
	Clusters []Cluster
}

type Cluster struct {
	types2.Metadata
	NodePools                []NodePool
	IPAllocationPolicy       IPAllocationPolicy
	MasterAuthorizedNetworks MasterAuthorizedNetworks
	NetworkPolicy            NetworkPolicy
	PrivateCluster           PrivateCluster
	LoggingService           types2.StringValue
	MonitoringService        types2.StringValue
	PodSecurityPolicy        PodSecurityPolicy
	MasterAuth               MasterAuth
	NodeConfig               NodeConfig
	EnableShieldedNodes      types2.BoolValue
	EnableLegacyABAC         types2.BoolValue
	ResourceLabels           types2.MapValue
	RemoveDefaultNodePool    types2.BoolValue
}

type NodeConfig struct {
	types2.Metadata
	ImageType              types2.StringValue
	WorkloadMetadataConfig WorkloadMetadataConfig
	ServiceAccount         types2.StringValue
	EnableLegacyEndpoints  types2.BoolValue
}

type WorkloadMetadataConfig struct {
	types2.Metadata
	NodeMetadata types2.StringValue
}

type MasterAuth struct {
	types2.Metadata
	ClientCertificate ClientCertificate
	Username          types2.StringValue
	Password          types2.StringValue
}

type ClientCertificate struct {
	types2.Metadata
	IssueCertificate types2.BoolValue
}

type PodSecurityPolicy struct {
	types2.Metadata
	Enabled types2.BoolValue
}

type PrivateCluster struct {
	types2.Metadata
	EnablePrivateNodes types2.BoolValue
}

type NetworkPolicy struct {
	types2.Metadata
	Enabled types2.BoolValue
}

type MasterAuthorizedNetworks struct {
	types2.Metadata
	Enabled types2.BoolValue
	CIDRs   []types2.StringValue
}

type IPAllocationPolicy struct {
	types2.Metadata
	Enabled types2.BoolValue
}

type NodePool struct {
	types2.Metadata
	Management Management
	NodeConfig NodeConfig
}

type Management struct {
	types2.Metadata
	EnableAutoRepair  types2.BoolValue
	EnableAutoUpgrade types2.BoolValue
}
