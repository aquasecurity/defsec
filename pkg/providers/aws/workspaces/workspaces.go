package workspaces

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type WorkSpaces struct {
	WorkSpaces []WorkSpace
}

type WorkSpace struct {
	defsecTypes.Metadata
	RootVolume Volume
	UserVolume Volume
}

type Volume struct {
	defsecTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}
