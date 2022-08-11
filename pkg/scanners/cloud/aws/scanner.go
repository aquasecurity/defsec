package aws

import (
	"context"
	"errors"
	"io"
	"io/fs"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/errs"

	adapter "github.com/aquasecurity/defsec/internal/adapters/cloud"
	cloudoptions "github.com/aquasecurity/defsec/internal/adapters/cloud/options"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/debug"
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/progress"
	_ "github.com/aquasecurity/defsec/pkg/rules"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

var _ ConfigurableAWSScanner = (*Scanner)(nil)

type Scanner struct {
	debug               debug.Logger
	options             []options.ScannerOption
	progressTracker     progress.Tracker
	region              string
	endpoint            string
	services            []string
	frameworks          []framework.Framework
	concurrencyStrategy concurrency.Strategy
}

func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {
	s.frameworks = frameworks
}

func AllSupportedServices() []string {
	return aws.AllServices()
}

func (s *Scanner) SetAWSRegion(region string) {
	s.region = region
}

func (s *Scanner) SetAWSEndpoint(endpoint string) {
	s.endpoint = endpoint
}

func (s *Scanner) SetAWSServices(services []string) {
	s.services = services
}

func (s *Scanner) SetConcurrencyStrategy(strategy concurrency.Strategy) {
	s.concurrencyStrategy = strategy
}

func New(opts ...options.ScannerOption) *Scanner {

	s := &Scanner{
		options:             opts,
		progressTracker:     progress.NoProgress,
		concurrencyStrategy: concurrency.DefaultStrategy,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Scanner) Scan(ctx context.Context) (results scan.Results, err error) {
	state, err := adapter.Adapt(ctx, cloudoptions.Options{
		ProgressTracker:     s.progressTracker,
		Region:              s.region,
		Endpoint:            s.endpoint,
		Services:            s.services,
		DebugWriter:         s.debug,
		ConcurrencyStrategy: s.concurrencyStrategy,
	})
	if err != nil {
		var adaptionError errs.AdapterError
		if errors.As(err, &adaptionError) {
			s.debug.Log("There were %d errors during adaption process: %s", len(adaptionError.Errors()), adaptionError)
		} else {
			return nil, err
		}
	}

	for _, rule := range rules.GetFrameworkRules(s.frameworks...) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if rule.Rule().RegoPackage != "" {
			continue
		}
		ruleResults := rule.Evaluate(state)
		if len(ruleResults) > 0 {
			s.debug.Log("Found %d results for %s", len(ruleResults), rule.Rule().AVDID)
			results = append(results, ruleResults...)
		}
	}
	return results, err
}

func (s *Scanner) Name() string {
	return "AWS API"
}

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.debug = debug.New(writer, "aws-api", "scanner")
}

func (s *Scanner) SetProgressTracker(t progress.Tracker) {
	s.progressTracker = t
}

func (s *Scanner) SetTraceWriter(writer io.Writer)      {}
func (s *Scanner) SetPerResultTracingEnabled(b bool)    {}
func (s *Scanner) SetPolicyDirs(s2 ...string)           {}
func (s *Scanner) SetDataDirs(s2 ...string)             {}
func (s *Scanner) SetPolicyNamespaces(s2 ...string)     {}
func (s *Scanner) SetSkipRequiredCheck(b bool)          {}
func (s *Scanner) SetPolicyReaders(readers []io.Reader) {}
func (s *Scanner) SetPolicyFilesystem(fs fs.FS)         {}
func (s *Scanner) SetUseEmbeddedPolicies(b bool)        {}
