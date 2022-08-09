package compute

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Instance struct {
	types2.Metadata
	Name                        types2.StringValue
	NetworkInterfaces           []NetworkInterface
	ShieldedVM                  ShieldedVMConfig
	ServiceAccount              ServiceAccount
	CanIPForward                types2.BoolValue
	OSLoginEnabled              types2.BoolValue
	EnableProjectSSHKeyBlocking types2.BoolValue
	EnableSerialPort            types2.BoolValue
	BootDisks                   []Disk
	AttachedDisks               []Disk
}

type ServiceAccount struct {
	types2.Metadata
	Email  types2.StringValue
	Scopes []types2.StringValue
}

type NetworkInterface struct {
	types2.Metadata
	Network     *Network
	SubNetwork  *SubNetwork
	HasPublicIP types2.BoolValue
	NATIP       types2.StringValue
}

type ShieldedVMConfig struct {
	types2.Metadata
	SecureBootEnabled          types2.BoolValue
	IntegrityMonitoringEnabled types2.BoolValue
	VTPMEnabled                types2.BoolValue
}
