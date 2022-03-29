package universal

import (
	"io"

	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation"
	"github.com/aquasecurity/defsec/pkg/scanners/dockerfile"
	"github.com/aquasecurity/defsec/pkg/scanners/kubernetes"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform"
)

type Option func(*Scanner)

func OptionWithDebug(w io.Writer) Option {
	return func(s *Scanner) {
		s.debugWriter = w
		s.terraformOpts = append(s.terraformOpts, terraform.OptionWithDebug(w))
		s.cloudformationOpts = append(s.cloudformationOpts, cloudformation.OptionWithDebug(w))
		s.dockerfileOpts = append(s.dockerfileOpts, dockerfile.OptionWithDebug(w))
		s.kubernetesOpts = append(s.kubernetesOpts, kubernetes.OptionWithDebug(w))
	}
}
