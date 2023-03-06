package transfer

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Transfer struct {
	ListServers []Servers
}

type Servers struct {
	Metadata  defsecTypes.Metadata
	ServerArn defsecTypes.StringValue
}
