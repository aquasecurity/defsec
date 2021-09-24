package state

import (
	"github.com/aquasecurity/defsec/provider/aws"
	"github.com/aquasecurity/defsec/provider/azure"
	"github.com/aquasecurity/defsec/provider/google"
)

type State struct {
	AWS    aws.AWS
	Azure  azure.Azure
	Google google.Google
}
