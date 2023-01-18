package provisioner

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Connection struct {
	Metadata           defsecTypes.Metadata
	Type               defsecTypes.StringValue
	User               defsecTypes.StringValue
	Password           defsecTypes.StringValue
	Host               defsecTypes.StringValue
	Port               defsecTypes.IntValue
	Timeout            defsecTypes.StringValue
	ScriptPath         defsecTypes.StringValue
	PrivateKey         defsecTypes.StringValue
	Certificate        defsecTypes.StringValue
	Agent              defsecTypes.BoolValue
	AgentIdentity      defsecTypes.StringValue
	HostKey            defsecTypes.StringValue
	TargetPlatform     defsecTypes.StringValue
	HTTPS              defsecTypes.BoolValue
	Insecure           defsecTypes.BoolValue
	UseNTLM            defsecTypes.BoolValue
	CACert             defsecTypes.StringValue
	BastionHost        defsecTypes.StringValue
	BastionHostKey     defsecTypes.StringValue
	BastionPort        defsecTypes.IntValue
	BastionUser        defsecTypes.StringValue
	BastionPassword    defsecTypes.StringValue
	BastionPrivateKey  defsecTypes.StringValue
	BastionCertificate defsecTypes.StringValue
	ProxyScheme        defsecTypes.StringValue
	ProxyHost          defsecTypes.StringValue
	ProxyPort          defsecTypes.IntValue
	ProxyUserName      defsecTypes.StringValue
	ProxyUserPassword  defsecTypes.StringValue
}
