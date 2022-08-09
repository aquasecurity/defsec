package gke

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type GKE struct {
	Clusters []Cluster
}

type Cluster struct {
	defsecTypes.Metadata
	NodePools                []NodePool
	IPAllocationPolicy       IPAllocationPolicy
	MasterAuthorizedNetworks MasterAuthorizedNetworks
	NetworkPolicy            NetworkPolicy
	PrivateCluster           PrivateCluster
	LoggingService           defsecTypes.StringValue
	MonitoringService        defsecTypes.StringValue
	PodSecurityPolicy        PodSecurityPolicy
	MasterAuth               MasterAuth
	NodeConfig               NodeConfig
	EnableShieldedNodes      defsecTypes.BoolValue
	EnableLegacyABAC         defsecTypes.BoolValue
	ResourceLabels           defsecTypes.MapValue
	RemoveDefaultNodePool    defsecTypes.BoolValue
}

type NodeConfig struct {
	defsecTypes.Metadata
	ImageType              defsecTypes.StringValue
	WorkloadMetadataConfig WorkloadMetadataConfig
	ServiceAccount         defsecTypes.StringValue
	EnableLegacyEndpoints  defsecTypes.BoolValue
}

type WorkloadMetadataConfig struct {
	defsecTypes.Metadata
	NodeMetadata defsecTypes.StringValue
}

type MasterAuth struct {
	defsecTypes.Metadata
	ClientCertificate ClientCertificate
	Username          defsecTypes.StringValue
	Password          defsecTypes.StringValue
}

type ClientCertificate struct {
	defsecTypes.Metadata
	IssueCertificate defsecTypes.BoolValue
}

type PodSecurityPolicy struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}

type PrivateCluster struct {
	defsecTypes.Metadata
	EnablePrivateNodes defsecTypes.BoolValue
}

type NetworkPolicy struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}

type MasterAuthorizedNetworks struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
	CIDRs   []defsecTypes.StringValue
}

type IPAllocationPolicy struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}

type NodePool struct {
	defsecTypes.Metadata
	Management Management
	NodeConfig NodeConfig
}

type Management struct {
	defsecTypes.Metadata
	EnableAutoRepair  defsecTypes.BoolValue
	EnableAutoUpgrade defsecTypes.BoolValue
}
