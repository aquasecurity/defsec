package nifcloud

import (
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/computing"
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/dns"
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/nas"
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/rdb"
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/sslcertificate"
)

type Nifcloud struct {
	Computing      computing.Computing
	DNS            dns.DNS
	NAS            nas.NAS
	RDB            rdb.RDB
	SSLCertificate sslcertificate.SSLCertificate
}
