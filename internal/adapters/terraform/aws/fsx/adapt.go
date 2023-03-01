package frauddetector

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/fsx"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) fsx.Fsx {
	return fsx.Fsx{
		Filesystems: adaptFileSystem(modules),
	}
}

func adaptFileSystem(modules terraform.Modules) []fsx.Filesystem {
	var FileSystem []fsx.Filesystem
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_fsx_backup") {
			FileSystem = append(FileSystem, adaptFileSystemType(resource, module))
		}
	}
	return FileSystem
}

func adaptFileSystemType(resource *terraform.Block, module *terraform.Module) fsx.Filesystem {

	TypeAttr := resource.GetAttribute("type")
	TypeVal := TypeAttr.AsStringValueOrDefault("", resource)

	return fsx.Filesystem{
		Metadata:       resource.GetMetadata(),
		FileSystemType: TypeVal,
	}
}
