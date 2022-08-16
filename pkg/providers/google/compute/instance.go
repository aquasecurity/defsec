package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Instance struct {
	defsecTypes.Metadata
	Name                        defsecTypes.StringValue
	NetworkInterfaces           []NetworkInterface
	ShieldedVM                  ShieldedVMConfig
	ServiceAccount              ServiceAccount
	CanIPForward                defsecTypes.BoolValue
	OSLoginEnabled              defsecTypes.BoolValue
	EnableProjectSSHKeyBlocking defsecTypes.BoolValue
	EnableSerialPort            defsecTypes.BoolValue
	BootDisks                   []Disk
	AttachedDisks               []Disk
}

type ServiceAccount struct {
	defsecTypes.Metadata
	Email     defsecTypes.StringValue
	IsDefault defsecTypes.BoolValue
	Scopes    []defsecTypes.StringValue
}

type NetworkInterface struct {
	defsecTypes.Metadata
	Network     *Network
	SubNetwork  *SubNetwork
	HasPublicIP defsecTypes.BoolValue
	NATIP       defsecTypes.StringValue
}

type ShieldedVMConfig struct {
	defsecTypes.Metadata
	SecureBootEnabled          defsecTypes.BoolValue
	IntegrityMonitoringEnabled defsecTypes.BoolValue
	VTPMEnabled                defsecTypes.BoolValue
}
