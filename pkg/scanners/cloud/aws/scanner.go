package aws

import (
	"context"
	"io"
	"io/fs"

	adapter "github.com/aquasecurity/defsec/internal/adapters/cloud"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/debug"
	"github.com/aquasecurity/defsec/pkg/progress"
	_ "github.com/aquasecurity/defsec/pkg/rules"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

type Scanner struct {
	debug           debug.Logger
	options         []options.ScannerOption
	progressTracker progress.Tracker
}

func New(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		options:         opts,
		progressTracker: progress.NoProgress,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Scanner) Scan(ctx context.Context) (results scan.Results, err error) {
	state, err := adapter.Adapt(ctx, s.progressTracker)
	if err != nil {
		panic(err)
	}

	for _, rule := range rules.GetRegistered() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if rule.Rule().RegoPackage != "" {
			continue
		}
		evalResult := rule.Evaluate(state)
		if len(evalResult) > 0 {
			s.debug.Log("Found %d results for %s", len(evalResult), rule.Rule().AVDID)
			for _, scanResult := range evalResult {

				ref := scanResult.Metadata().Reference()

				if ref == nil && scanResult.Metadata().Parent() != nil {
					ref = scanResult.Metadata().Parent().Reference()
				}

				results = append(results, scanResult)

			}
		}
	}

	return results, nil

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
