package universal

import (
	"context"
	"fmt"
	"io"
	"io/fs"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/scanners"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation"
	"github.com/aquasecurity/defsec/pkg/scanners/dockerfile"
	"github.com/aquasecurity/defsec/pkg/scanners/kubernetes"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform"
)

var _ scanners.Scanner = (*Scanner)(nil)

type Scanner struct {
	debugWriter        io.Writer
	scanners           []scanners.Scanner
	terraformOpts      []terraform.Option
	cloudformationOpts []cloudformation.Option
	dockerfileOpts     []dockerfile.Option
	kubernetesOpts     []kubernetes.Option
}

func (s *Scanner) debug(format string, args ...interface{}) {
	if s.debugWriter == nil {
		return
	}
	prefix := "[debug:scan:universal] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func New(opts ...Option) *Scanner {
	s := &Scanner{}
	for _, opt := range opts {
		opt(s)
	}
	s.scanners = []scanners.Scanner{
		terraform.New(s.terraformOpts...),
		cloudformation.New(s.cloudformationOpts...),
		dockerfile.NewScanner(s.dockerfileOpts...),
		kubernetes.NewScanner(s.kubernetesOpts...),
	}
	return s
}

func (s *Scanner) ScanFS(ctx context.Context, fs fs.FS, dir string) (scan.Results, error) {
	var results scan.Results
	for _, inner := range s.scanners {
		s.debug("Scanning with %T...\n", inner)
		innerResults, err := inner.ScanFS(ctx, fs, dir)
		if err != nil {
			return nil, err
		}
		results = append(results, innerResults...)
	}
	return results, nil
}
