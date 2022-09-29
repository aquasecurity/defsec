package workspaces

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type WorkSpaces struct {
	WorkSpaces []WorkSpace
}

type WorkSpace struct {
	Metadata   defsecTypes.Metadata
	RootVolume Volume
	UserVolume Volume
}

type Volume struct {
	Metadata   defsecTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}
