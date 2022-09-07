package formatters

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/scan"
)

func outputSimple(b ConfigurableFormatter, results scan.Results) error {
	for _, res := range results.GetFailed() {
		_, _ = fmt.Fprintf(
			b.Writer(),
			"\x1b[31m%s \x1b[32m%s \x1b[33m%s\x1b[0m\n",
			res.Rule().AVDID,
			res.Rule().LongID(),
			res.Range().String(),
		)
	}
	return nil
}
