package workspaces

import "github.com/aquasecurity/defsec/types"

type WorkSpaces struct {
	WorkSpaces []WorkSpace
}

type WorkSpace struct {
	RootVolume Volume
	UserVolume Volume
}

type Volume struct {
	Encryption Encryption
}

type Encryption struct {
	Enabled types.BoolValue
}
