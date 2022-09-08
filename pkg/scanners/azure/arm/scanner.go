package arm

import (
	"context"
	"io"
	"io/fs"

	"github.com/aquasecurity/defsec/internal/adapters/arm"

	"github.com/aquasecurity/defsec/pkg/rules"
	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scanners/azure"

	"github.com/aquasecurity/defsec/pkg/debug"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/scanners"
	"github.com/aquasecurity/defsec/pkg/scanners/azure/arm/parser"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

var _ scanners.FSScanner = (*Scanner)(nil)
var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	scannerOptions []options.ScannerOption
	parserOptions  []options.ParserOption
	debugWriter    io.Writer
	debug          debug.Logger
	frameworks     []framework.Framework
}

func New(opts ...options.ScannerOption) *Scanner {
	scanner := &Scanner{
		scannerOptions: opts,
	}
	for _, opt := range opts {
		opt(scanner)
	}
	return scanner
}

func (s *Scanner) Name() string {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) ScanFS(ctx context.Context, fs fs.FS, dir string) (scan.Results, error) {
	//TODO implement me
	p := parser.New(fs, s.parserOptions...)
	deployments, err := p.ParseFS(ctx, dir)
	if err != nil {
		return nil, err
	}
	return s.scanDeployments(ctx, deployments)
}

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.debug = debug.New(writer, "azure", "arm")
	s.parserOptions = append(s.parserOptions, options.ParserWithDebug(writer))
}

func (s *Scanner) SetTraceWriter(writer io.Writer) {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) SetPerResultTracingEnabled(b bool) {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) SetPolicyDirs(s2 ...string) {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) SetDataDirs(s2 ...string) {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) SetPolicyNamespaces(s2 ...string) {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) SetSkipRequiredCheck(b bool) {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) SetPolicyReaders(readers []io.Reader) {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) SetPolicyFilesystem(fs fs.FS) {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) SetUseEmbeddedPolicies(b bool) {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {
	s.frameworks = frameworks
}

func (s *Scanner) scanDeployments(ctx context.Context, deployments []azure.Deployment) (scan.Results, error) {

	var results scan.Results

	for _, deployment := range deployments {
		// TODO: adapt each deployment into a state
		cloudState := s.adaptDeployment(ctx, deployment)
		for _, rule := range rules.GetRegistered(s.frameworks...) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			if rule.Rule().RegoPackage != "" {
				continue
			}
			ruleResults := rule.Evaluate(cloudState)
			if len(ruleResults) > 0 {
				s.debug.Log("Found %d results for %s", len(ruleResults), rule.Rule().AVDID)
				results = append(results, ruleResults...)
			}
		}
	}

	return results, nil
}

func (s *Scanner) adaptDeployment(ctx context.Context, deployment azure.Deployment) *state.State {
	return arm.Adapt(ctx, deployment)
}
