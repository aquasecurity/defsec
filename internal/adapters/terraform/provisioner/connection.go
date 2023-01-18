package provisioner

import (
	"github.com/aquasecurity/defsec/pkg/providers/provisioner"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

// getStringValue is AsStringValueOrDefault for multiple blocks
func getStringValue(fallback *terraform.Block, provConn *terraform.Block, resourceConn *terraform.Block, name string, defaultValue string) defsecTypes.StringValue {
	if attr := provConn.GetAttribute(name); attr.IsNotNil() {
		return attr.AsStringValueOrDefault(defaultValue, provConn)
	}
	if attr := resourceConn.GetAttribute(name); attr.IsNotNil() {
		return attr.AsStringValueOrDefault(defaultValue, resourceConn)
	}
	return defsecTypes.StringDefault(defaultValue, fallback.GetMetadata())
}

// getIntValue is AsIntValueOrDefault for multiple blocks
func getIntValue(fallback *terraform.Block, provConn *terraform.Block, resourceConn *terraform.Block, name string, defaultValue int) defsecTypes.IntValue {
	if attr := provConn.GetAttribute(name); attr.IsNotNil() {
		return attr.AsIntValueOrDefault(defaultValue, provConn)
	}
	if attr := resourceConn.GetAttribute(name); attr.IsNotNil() {
		return attr.AsIntValueOrDefault(defaultValue, resourceConn)
	}
	return defsecTypes.IntDefault(defaultValue, fallback.GetMetadata())
}

// getBoolValue is AsBoolValueOrDefault for multiple blocks
func getBoolValue(fallback *terraform.Block, provConn *terraform.Block, resourceConn *terraform.Block, name string, defaultValue bool) defsecTypes.BoolValue {
	if attr := provConn.GetAttribute(name); attr.IsNotNil() {
		return attr.AsBoolValueOrDefault(defaultValue, provConn)
	}
	if attr := resourceConn.GetAttribute(name); attr.IsNotNil() {
		return attr.AsBoolValueOrDefault(defaultValue, resourceConn)
	}
	return defsecTypes.BoolDefault(defaultValue, fallback.GetMetadata())
}

// adaptConnection parses a set of
func adaptConnection(resource *terraform.Block, prov *terraform.Block) provisioner.Connection {
	// Extract the "connection" blocks from the resource and the provider
	provConn := prov.GetBlock("connection")
	resourceConn := resource.GetBlock("connection")
	// The fallback metadata for default values is the provisioner block
	fallback := prov
	if provConn.IsNotNil() {
		fallback = provConn
	} else if resourceConn.IsNotNil() {
		fallback = resourceConn
	}
	fallbackMetadata := fallback.GetMetadata()
	// Only a handful of keys are shared for ssh and winrm
	conn := provisioner.Connection{
		Metadata:           fallbackMetadata,
		Type:               getStringValue(fallback, provConn, resourceConn, "type", "ssh"),
		User:               defsecTypes.StringDefault("", fallbackMetadata),
		Password:           getStringValue(fallback, provConn, resourceConn, "password", ""),
		Host:               getStringValue(fallback, provConn, resourceConn, "host", ""),
		Port:               defsecTypes.IntDefault(0, fallbackMetadata),
		Timeout:            getStringValue(fallback, provConn, resourceConn, "timeout", "5m"),
		ScriptPath:         defsecTypes.StringDefault("", fallbackMetadata),
		PrivateKey:         getStringValue(fallback, provConn, resourceConn, "private_key", ""),
		Certificate:        getStringValue(fallback, provConn, resourceConn, "certificate", ""),
		Agent:              getBoolValue(fallback, provConn, resourceConn, "certificate", true),
		AgentIdentity:      getStringValue(fallback, provConn, resourceConn, "agent_identity", ""),
		HostKey:            getStringValue(fallback, provConn, resourceConn, "host_key", ""),
		TargetPlatform:     getStringValue(fallback, provConn, resourceConn, "target_platform", ""),
		HTTPS:              getBoolValue(fallback, provConn, resourceConn, "https", false),
		Insecure:           getBoolValue(fallback, provConn, resourceConn, "insecure", false),
		UseNTLM:            getBoolValue(fallback, provConn, resourceConn, "use_ntlm", false),
		CACert:             getStringValue(fallback, provConn, resourceConn, "cacert", ""),
		BastionPort:        defsecTypes.IntDefault(0, fallbackMetadata),
		BastionUser:        defsecTypes.StringDefault("", fallbackMetadata),
		BastionPassword:    defsecTypes.StringDefault("", fallbackMetadata),
		BastionPrivateKey:  defsecTypes.StringDefault("", fallbackMetadata),
		BastionCertificate: defsecTypes.StringDefault("", fallbackMetadata),
		BastionHost:        getStringValue(fallback, provConn, resourceConn, "bastion_host", ""),
		BastionHostKey:     getStringValue(fallback, provConn, resourceConn, "bastion_host_key", ""),
		ProxyScheme:        getStringValue(fallback, provConn, resourceConn, "proxy_scheme", ""),
		ProxyHost:          getStringValue(fallback, provConn, resourceConn, "proxy_host", ""),
		ProxyPort:          getIntValue(fallback, provConn, resourceConn, "proxy_host", 0),
		ProxyUserName:      getStringValue(fallback, provConn, resourceConn, "proxy_user_name", ""),
		ProxyUserPassword:  getStringValue(fallback, provConn, resourceConn, "proxy_user_password", ""),
	}
	// Some defaults change depending on the connection type
	var defaultUser string
	var defaultPort int
	var defaultTargetPlatform string
	switch conn.Type.Value() {
	case "ssh":
		defaultUser = "root"
		defaultPort = 22
		defaultTargetPlatform = "unix"
	case "winrm":
		defaultUser = "Administrator"
		defaultPort = 5985
		defaultTargetPlatform = "windows"
	}
	conn.User = getStringValue(fallback, provConn, resourceConn, "user", defaultUser)
	conn.Port = getIntValue(fallback, provConn, resourceConn, "port", defaultPort)
	conn.TargetPlatform = getStringValue(fallback, provConn, resourceConn, "target_platform", defaultTargetPlatform)
	// The script path changes based on the target platform
	var defaultScriptPath string
	switch conn.TargetPlatform.Value() {
	case "unix":
		defaultScriptPath = "/tmp/terraform_%RAND%.sh"
	case "windows":
		defaultScriptPath = "C:/Temp/terraform_%RAND%.cmd"
	}
	conn.ScriptPath = getStringValue(fallback, provConn, resourceConn, "script_path", defaultScriptPath)
	// Finally, the bastion settings default to the values for their SSH equivilents
	conn.BastionPort = getIntValue(fallback, provConn, resourceConn, "bastion_port", conn.Port.Value())
	conn.BastionUser = getStringValue(fallback, provConn, resourceConn, "bastion_port", conn.User.Value())
	conn.BastionPassword = getStringValue(fallback, provConn, resourceConn, "bastion_password", conn.Password.Value())
	conn.BastionPrivateKey = getStringValue(fallback, provConn, resourceConn, "bastion_private_key", conn.PrivateKey.Value())
	conn.BastionCertificate = getStringValue(fallback, provConn, resourceConn, "bastion_certificate", conn.Certificate.Value())
	return conn
}
