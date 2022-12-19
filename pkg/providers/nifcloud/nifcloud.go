package nifcloud

import (
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/computing"
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/dns"
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/sslcertificate"
)

type Nifcloud struct {
	Computing      computing.Computing
	DNS            dns.DNS
	SSLCertificate sslcertificate.SSLCertificate
}
