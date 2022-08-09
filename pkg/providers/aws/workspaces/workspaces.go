package workspaces

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type WorkSpaces struct {
	WorkSpaces []WorkSpace
}

type WorkSpace struct {
	types2.Metadata
	RootVolume Volume
	UserVolume Volume
}

type Volume struct {
	types2.Metadata
	Encryption Encryption
}

type Encryption struct {
	types2.Metadata
	Enabled types2.BoolValue
}
