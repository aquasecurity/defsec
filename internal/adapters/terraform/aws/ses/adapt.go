package ses

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ses"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) ses.Ses {
	return ses.Ses{
		ListIdentities: nil,
	}
}
