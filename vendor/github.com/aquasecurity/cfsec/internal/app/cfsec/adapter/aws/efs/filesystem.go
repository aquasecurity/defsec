package efs

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/efs"
)

func getFileSystems(ctx parser.FileContext) (filesystems []efs.FileSystem) {

	filesystemResources := ctx.GetResourceByType("AWS::EFS::FileSystem")

	for _, r := range filesystemResources {

		filesystem := efs.FileSystem{
			Metadata:  r.Metadata(),
			Encrypted: r.GetBoolProperty("Encrypted"),
		}

		filesystems = append(filesystems, filesystem)
	}

	return filesystems
}
