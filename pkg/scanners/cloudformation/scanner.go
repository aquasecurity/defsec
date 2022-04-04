package cloudformation

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"sync"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"

	"github.com/aquasecurity/defsec/pkg/scan"

	adapter "github.com/aquasecurity/defsec/internal/adapters/cloudformation"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/rego"
	_ "github.com/aquasecurity/defsec/pkg/rules"
	"github.com/aquasecurity/defsec/pkg/scanners"
)

var _ scanners.Scanner = (*Scanner)(nil)

type Scanner struct {
	includePassed     bool
	includeIgnored    bool
	excludedRuleIDs   []string
	ignoreCheckErrors bool
	debugWriter       io.Writer
	traceWriter       io.Writer
	policyDirs        []string
	dataDirs          []string
	policyNamespaces  []string
	parser            *parser.Parser
	regoScanner       *rego.Scanner
	sync.Mutex
}

// New creates a new Scanner
func New(options ...Option) *Scanner {
	s := &Scanner{
		ignoreCheckErrors: true,
		parser:            parser.New(),
	}
	for _, option := range options {
		option(s)
	}
	return s
}

func (s *Scanner) debug(format string, args ...interface{}) {
	if s.debugWriter == nil {
		return
	}
	prefix := "[debug:scan:cloudformation] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (s *Scanner) initRegoScanner(srcFS fs.FS) (*rego.Scanner, error) {
	s.Lock()
	defer s.Unlock()
	if s.regoScanner != nil {
		return s.regoScanner, nil
	}
	regoOpts := []rego.Option{
		rego.OptionWithPolicyNamespaces(true, s.policyNamespaces...),
		rego.OptionWithDataDirs(s.dataDirs...),
	}
	if s.traceWriter != nil {
		regoOpts = append(regoOpts, rego.OptionWithTrace(s.traceWriter))
	}
	regoScanner := rego.NewScanner(regoOpts...)
	if err := regoScanner.LoadPolicies(true, srcFS, s.policyDirs, nil); err != nil {
		return nil, err
	}
	s.regoScanner = regoScanner
	return regoScanner, nil
}

func (s *Scanner) ScanFS(ctx context.Context, fs fs.FS, dir string) (results scan.Results, err error) {

	contexts, err := s.parser.ParseFS(ctx, fs, dir)
	if err != nil {
		return nil, err
	}

	if len(contexts) == 0 {
		return nil, nil
	}

	regoScanner, err := s.initRegoScanner(fs)
	if err != nil {
		return nil, err
	}

	for _, cfCtx := range contexts {
		if cfCtx == nil {
			continue
		}
		fileResults, err := s.scanFileContext(ctx, regoScanner, cfCtx)
		if err != nil {
			return nil, err
		}
		results = append(results, fileResults...)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Rule().AVDID < results[j].Rule().AVDID
	})
	return results, nil
}

func (s *Scanner) ScanFile(ctx context.Context, fs fs.FS, path string) (scan.Results, error) {

	cfCtx, err := s.parser.ParseFile(ctx, fs, path)
	if err != nil {
		return nil, err
	}

	regoScanner, err := s.initRegoScanner(fs)
	if err != nil {
		return nil, err
	}

	results, err := s.scanFileContext(ctx, regoScanner, cfCtx)
	if err != nil {
		return nil, err
	}
	results.SetSourceAndFilesystem("", fs)

	sort.Slice(results, func(i, j int) bool {
		return results[i].Rule().AVDID < results[j].Rule().AVDID
	})
	return results, nil
}

func (s *Scanner) scanFileContext(ctx context.Context, regoScanner *rego.Scanner, cfCtx *parser.FileContext) (results scan.Results, err error) {
	state := adapter.Adapt(*cfCtx)
	if state == nil {
		return nil, nil
	}
	for _, rule := range rules.GetRegistered() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		evalResult := rule.Evaluate(state)
		if len(evalResult) > 0 {
			s.debug("Found %d results for %s", len(evalResult), rule.Rule().AVDID)
			for _, scanResult := range evalResult {
				if s.isExcluded(scanResult) || isIgnored(scanResult) {
					scanResult.OverrideStatus(scan.StatusIgnored)
				}

				ref := scanResult.Metadata().Reference()

				if ref == nil && scanResult.Metadata().Parent() != nil {
					ref = scanResult.Metadata().Parent().Reference()
				}

				reference := ref.(*parser.CFReference)
				description := getDescription(scanResult, reference)
				scanResult.OverrideDescription(description)
				if scanResult.Status() == scan.StatusPassed && !s.includePassed {
					continue
				}

				results = append(results, scanResult)
			}
		}
	}
	regoResults, err := regoScanner.ScanInput(ctx, rego.Input{
		Path:     cfCtx.Metadata().Range().GetFilename(),
		Contents: state,
		Type:     types.SourceDefsec,
	})
	if err != nil {
		return nil, fmt.Errorf("rego scan error: %w", err)
	}
	return append(results, regoResults...), nil
}

func (s *Scanner) isExcluded(result scan.Result) bool {
	for _, excluded := range s.excludedRuleIDs {
		if strings.EqualFold(excluded, result.Flatten().RuleID) {
			return true
		}
	}
	return false
}

func getDescription(scanResult scan.Result, location *parser.CFReference) string {
	switch scanResult.Status() {
	case scan.StatusPassed:
		return fmt.Sprintf("Resource '%s' passed check: %s", location.LogicalID(), scanResult.Rule().Summary)
	case scan.StatusIgnored:
		return fmt.Sprintf("Resource '%s' had check ignored: %s", location.LogicalID(), scanResult.Rule().Summary)
	default:
		return scanResult.Description()
	}
}
