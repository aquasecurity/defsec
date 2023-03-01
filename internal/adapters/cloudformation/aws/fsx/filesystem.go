package fsx

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/fsx"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getFileSystem(ctx parser.FileContext) (filesystemtype []fsx.Filesystem) {

	getFileSystemTypes := ctx.GetResourcesByType("AWS::FSx::FileSystem")

	for _, r := range getFileSystemTypes {

		ds := fsx.Filesystem{
			Metadata:       r.Metadata(),
			FileSystemType: r.GetStringProperty("FileSystemTypes"),
		}
		filesystemtype = append(filesystemtype, ds)
	}

	return filesystemtype
}
