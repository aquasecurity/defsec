package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Compute struct {
	LinuxVirtualMachines   []LinuxVirtualMachine
	WindowsVirtualMachines []WindowsVirtualMachine
	ManagedDisks           []ManagedDisk
	VirtualMachineList     VirtualMachineList
}

type VirtualMachineList struct {
	Value []VirtualMachines `json:"value"`
}

type VirtualMachine struct {
	Metadata   defsecTypes.Metadata
	CustomData defsecTypes.StringValue // NOT base64 encoded
}

type VirtualMachines struct {
	Metadata   defsecTypes.Metadata
	Id         string
	Name       string
	Properties Properties
}

type Properties struct {
	Metadata           defsecTypes.Metadata
	ProvisioningState  string
	VmId               string
	DiagnosticsProfile DiagnosticsProfile
}

type DiagnosticsProfile struct {
	Metadata        defsecTypes.Metadata
	BootDiagnostics BootDiagnostics
}

type BootDiagnostics struct {
	Metadata defsecTypes.Metadata
	Enabled  bool
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
