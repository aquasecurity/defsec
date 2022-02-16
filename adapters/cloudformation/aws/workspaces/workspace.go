package workspaces

import (
	"github.com/aquasecurity/defsec/provider/aws/workspaces"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

func getWorkSpaces(ctx parser.FileContext) (workSpaces []workspaces.WorkSpace) {
	for _, r := range ctx.GetResourceByType("AWS::WorkSpaces::Workspace") {
		workspace := workspaces.WorkSpace{
			Metadata: r.Metadata(),
			RootVolume: workspaces.Volume{
				Encryption: workspaces.Encryption{
					Enabled: r.GetBoolProperty("RootVolumeEncryptionEnabled"),
				},
			},
			UserVolume: workspaces.Volume{
				Encryption: workspaces.Encryption{
					Enabled: r.GetBoolProperty("UserVolumeEncryptionEnabled"),
				},
			},
		}

		workSpaces = append(workSpaces, workspace)
	}
	return workSpaces
}
