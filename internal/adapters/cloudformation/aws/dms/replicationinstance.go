package dms

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/dms"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getReplicationInstances(ctx parser.FileContext) (replicationinstances []dms.ReplicationInstance) {

	replicationinstanceResource := ctx.GetResourcesByType("AWS::DMS::ReplicationInstance")

	for _, r := range replicationinstanceResource {
		replicationinstance := dms.ReplicationInstance{
			Metadata:                r.Metadata(),
			AutoMinorVersionUpgrade: r.GetBoolProperty("AutoMinorVersionUpgrade"),
			MultiAZ:                 r.GetBoolProperty("MultiAZ"),
			PubliclyAccessible:      r.GetBoolProperty("PubliclyAccessible"),
		}

		replicationinstances = append(replicationinstances, replicationinstance)
	}

	return replicationinstances
}
