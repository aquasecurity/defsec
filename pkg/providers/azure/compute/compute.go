package compute

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Compute struct {
	LinuxVirtualMachines   []LinuxVirtualMachine
	WindowsVirtualMachines []WindowsVirtualMachine
	ManagedDisks           []ManagedDisk
}

type VirtualMachine struct {
	types2.Metadata
	CustomData types2.StringValue // NOT base64 encoded
}

type LinuxVirtualMachine struct {
	types2.Metadata
	VirtualMachine
	OSProfileLinuxConfig OSProfileLinuxConfig
}

type WindowsVirtualMachine struct {
	types2.Metadata
	VirtualMachine
}

type OSProfileLinuxConfig struct {
	types2.Metadata
	DisablePasswordAuthentication types2.BoolValue
}

type ManagedDisk struct {
	types2.Metadata
	Encryption Encryption
}

type Encryption struct {
	types2.Metadata
	Enabled types2.BoolValue
}
