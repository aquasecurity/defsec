package universal

import (
	"context"
	"io/fs"

	"github.com/aquasecurity/defsec/pkg/scanners/aws/cloud"
	"github.com/aquasecurity/defsec/pkg/scanners/aws/cloudformation"
	"github.com/aquasecurity/defsec/pkg/scanners/dockerfile"
	"github.com/aquasecurity/defsec/pkg/scanners/genericconfig/json"
	"github.com/aquasecurity/defsec/pkg/scanners/genericconfig/toml"
	"github.com/aquasecurity/defsec/pkg/scanners/genericconfig/yaml"
	"github.com/aquasecurity/defsec/pkg/scanners/k8s/helm"
	"github.com/aquasecurity/defsec/pkg/scanners/k8s/kubernetes"
	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform"
)

type nestableFSScanners interface {
	scanners.FSScanner
	options.ConfigurableScanner
}

type nestableAPIScanners interface {
	scanners.APIScanner
	options.ConfigurableScanner
}

var _ scanners.FSScanner = (*Scanner)(nil)

type Scanner struct {
	fsScanners  []nestableFSScanners
	apiScanners []nestableAPIScanners
}

func New(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		fsScanners: []nestableFSScanners{
			terraform.New(opts...),
			cloudformation.New(opts...),
			dockerfile.NewScanner(opts...),
			kubernetes.NewScanner(opts...),
			json.NewScanner(opts...),
			yaml.NewScanner(opts...),
			toml.NewScanner(opts...),
			helm.New(opts...),
		},
		apiScanners: []nestableAPIScanners{
			cloud.New(opts...),
		},
	}
	return s
}

func (s *Scanner) Name() string {
	return "Universal"
}

func (s *Scanner) ScanFS(ctx context.Context, fs fs.FS, dir string) (scan.Results, error) {
	var results scan.Results
	for _, inner := range s.fsScanners {
		innerResults, err := inner.ScanFS(ctx, fs, dir)
		if err != nil {
			return nil, err
		}
		results = append(results, innerResults...)
	}
	return results, nil
}

func (s *Scanner) Scan(ctx context.Context) (scan.Results, error) {
	var results scan.Results

	for _, inner := range s.apiScanners {
		innerResults, err := inner.Scan(ctx)
		if err != nil {
			return nil, err
		}
		results = append(results, innerResults...)
	}
	return results, nil
}
