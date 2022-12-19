package nifcloud

import (
	"github.com/aquasecurity/defsec/internal/adapters/terraform/nifcloud/computing"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/nifcloud/dns"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/nifcloud/sslcertificate"
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) nifcloud.Nifcloud {
	return nifcloud.Nifcloud{
		Computing:      computing.Adapt(modules),
		DNS:            dns.Adapt(modules),
		SSLCertificate: sslcertificate.Adapt(modules),
	}
}
