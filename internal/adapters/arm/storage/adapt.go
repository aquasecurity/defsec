package storage

import (
	"github.com/aquasecurity/defsec/pkg/providers/azure/storage"
	"github.com/aquasecurity/defsec/pkg/scanners/azure"
)

func Adapt(deployment azure.Deployment) storage.Storage {
	return storage.Storage{}
}
