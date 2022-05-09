package universal

import (
	"context"
	"io/fs"

	"github.com/aquasecurity/defsec/pkg/scanners/helm"
	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/scanners/json"
	"github.com/aquasecurity/defsec/pkg/scanners/toml"
	"github.com/aquasecurity/defsec/pkg/scanners/yaml"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/scanners"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation"
	"github.com/aquasecurity/defsec/pkg/scanners/dockerfile"
	"github.com/aquasecurity/defsec/pkg/scanners/kubernetes"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform"
)

type nestableScanner interface {
	scanners.Scanner
	options.ConfigurableScanner
}

var _ scanners.Scanner = (*Scanner)(nil)

type Scanner struct {
	scanners []nestableScanner
}

func New(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		scanners: []nestableScanner{
			terraform.New(opts...),
			cloudformation.New(opts...),
			dockerfile.NewScanner(opts...),
			kubernetes.NewScanner(opts...),
			json.NewScanner(opts...),
			yaml.NewScanner(opts...),
			toml.NewScanner(opts...),
			helm.New(opts...),
		},
	}
	return s
}

func (s *Scanner) Name() string {
	return "Universal"
}

func (s *Scanner) ScanFS(ctx context.Context, fs fs.FS, dir string) (scan.Results, error) {
	var results scan.Results
	for _, inner := range s.scanners {
		innerResults, err := inner.ScanFS(ctx, fs, dir)
		if err != nil {
			return nil, err
		}
		results = append(results, innerResults...)
	}
	return results, nil
}
