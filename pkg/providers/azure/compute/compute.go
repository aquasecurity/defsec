package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Compute struct {
	LinuxVirtualMachines   []LinuxVirtualMachine
	WindowsVirtualMachines []WindowsVirtualMachine
	ManagedDisks           []ManagedDisk
	VirtualMachineList     []VirtualMachines
}

type VirtualMachine struct {
	Metadata   defsecTypes.Metadata
	CustomData defsecTypes.StringValue // NOT base64 encoded
}

type VirtualMachines struct {
	Metadata   defsecTypes.Metadata
	Id         defsecTypes.StringValue
	Name       defsecTypes.StringValue
	Properties Properties
}

type Properties struct {
	Metadata           defsecTypes.Metadata
	ProvisioningState  defsecTypes.StringValue
	VmId               defsecTypes.StringValue
	DiagnosticsProfile DiagnosticsProfile
}

type DiagnosticsProfile struct {
	Metadata        defsecTypes.Metadata
	BootDiagnostics BootDiagnostics
}

type BootDiagnostics struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type LinuxVirtualMachine struct {
	Metadata defsecTypes.Metadata
	VirtualMachine
	OSProfileLinuxConfig OSProfileLinuxConfig
}

type WindowsVirtualMachine struct {
	Metadata defsecTypes.Metadata
	VirtualMachine
}

type OSProfileLinuxConfig struct {
	Metadata                      defsecTypes.Metadata
	DisablePasswordAuthentication defsecTypes.BoolValue
}

type ManagedDisk struct {
	Metadata   defsecTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}
