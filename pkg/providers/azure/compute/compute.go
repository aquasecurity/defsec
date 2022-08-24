package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Compute struct {
	LinuxVirtualMachines   []LinuxVirtualMachine
	WindowsVirtualMachines []WindowsVirtualMachine
	ManagedDisks           []ManagedDisk
}

type VirtualMachine struct {
	defsecTypes.Metadata
	CustomData defsecTypes.StringValue // NOT base64 encoded
}

type LinuxVirtualMachine struct {
	defsecTypes.Metadata
	VirtualMachine
	OSProfileLinuxConfig OSProfileLinuxConfig
}

type WindowsVirtualMachine struct {
	defsecTypes.Metadata
	VirtualMachine
}

type OSProfileLinuxConfig struct {
	defsecTypes.Metadata
	DisablePasswordAuthentication defsecTypes.BoolValue
}

type ManagedDisk struct {
	defsecTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}
