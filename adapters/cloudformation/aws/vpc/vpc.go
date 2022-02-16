package vpc

import (
	"github.com/aquasecurity/defsec/provider/aws/vpc"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result vpc.VPC) {

	result.DefaultVPCs = getDefaultVPCs()
	result.NetworkACLs = getNetworkACLs(cfFile)
	result.SecurityGroups = getSecurityGroups(cfFile)

	return result
}

func getDefaultVPCs() []vpc.DefaultVPC {
	// NOTE: it appears you can no longer create default VPCs via CF
	return nil
}
