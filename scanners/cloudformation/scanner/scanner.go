package scanner

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"

	"github.com/aquasecurity/defsec/scanners"

	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/rego"

	adapter "github.com/aquasecurity/defsec/adapters/cloudformation"

	_ "github.com/aquasecurity/defsec/loader"
	"github.com/aquasecurity/defsec/rules"

	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
)

type Scanner struct {
	includePassed     bool
	includeIgnored    bool
	excludedRuleIDs   []string
	ignoreCheckErrors bool
	debugWriter       io.Writer
	policyDirs        []string
	policyNamespaces  []string
	parser            *parser.Parser
}

var _ scanners.Scanner = (*Scanner)(nil)

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
	prefix := "[debug:scan] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (s *Scanner) initRegoScanner() (*rego.Scanner, error) {
	regoScanner := rego.NewScanner(rego.OptionWithPolicyNamespaces(true, s.policyNamespaces...))
	if err := regoScanner.LoadPolicies(true, s.policyDirs...); err != nil {
		return nil, err
	}
	return regoScanner, nil
}

func (s *Scanner) ScanFS(ctx context.Context, fs fs.FS, dir string) (results rules.Results, err error) {

	contexts, err := s.parser.ParseFS(ctx, fs, dir)
	if err != nil {
		return nil, err
	}

	regoScanner, err := s.initRegoScanner()
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

func (s *Scanner) ScanFile(ctx context.Context, fs fs.FS, path string) (rules.Results, error) {

	cfCtx, err := s.parser.ParseFile(ctx, fs, path)
	if err != nil {
		return nil, err
	}

	regoScanner, err := s.initRegoScanner()
	if err != nil {
		return nil, err
	}

	results, err := s.scanFileContext(ctx, regoScanner, cfCtx)
	if err != nil {
		return nil, err
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Rule().AVDID < results[j].Rule().AVDID
	})
	return results, nil
}

func (s *Scanner) scanFileContext(ctx context.Context, regoScanner *rego.Scanner, cfCtx *parser.FileContext) (results rules.Results, err error) {
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
		s.debug("Executing rule: %s", rule.Rule().AVDID)
		evalResult := rule.Evaluate(state)
		if len(evalResult) > 0 {
			s.debug("Found %d results for %s", len(evalResult), rule.Rule().AVDID)
			for _, scanResult := range evalResult {
				if s.isExcluded(scanResult) || isIgnored(scanResult) {
					scanResult.OverrideStatus(rules.StatusIgnored)
				}

				ref := scanResult.Metadata().Reference()

				if ref == nil && scanResult.Metadata().Parent() != nil {
					ref = scanResult.Metadata().Parent().Reference()
				}

				reference := ref.(*parser.CFReference)
				description := getDescription(scanResult, reference)
				scanResult.OverrideDescription(description)
				if scanResult.Status() == rules.StatusPassed && !s.includePassed {
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

func (s *Scanner) isExcluded(result rules.Result) bool {
	for _, excluded := range s.excludedRuleIDs {
		if strings.EqualFold(excluded, result.Flatten().RuleID) {
			return true
		}
	}
	return false
}

func getDescription(scanResult rules.Result, location *parser.CFReference) string {
	switch scanResult.Status() {
	case rules.StatusPassed:
		return fmt.Sprintf("Resource '%s' passed check: %s", location.LogicalID(), scanResult.Rule().Summary)
	case rules.StatusIgnored:
		return fmt.Sprintf("Resource '%s' had check ignored: %s", location.LogicalID(), scanResult.Rule().Summary)
	default:
		return scanResult.Description()
	}
}
