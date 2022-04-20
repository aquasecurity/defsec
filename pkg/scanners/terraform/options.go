package terraform

import (
	"io"
	"strings"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform/executor"
)

type Option func(s *Scanner)

func OptionWithAlternativeIDProvider(f func(string) []string) Option {
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionWithAlternativeIDProvider(f))
	}
}

func OptionWithSeverityOverrides(overrides map[string]string) Option {
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionWithSeverityOverrides(overrides))
	}
}

func OptionWithDebug(w io.Writer) Option {
	return func(s *Scanner) {
		s.debugWriter = w
		s.executorOpt = append(s.executorOpt, executor.OptionWithDebugWriter(w))
		s.parserOpt = append(s.parserOpt, parser.OptionWithDebugWriter(w))
	}
}

func OptionWithTrace(w io.Writer) Option {
	return func(s *Scanner) {
		s.traceWriter = w
	}
}

func OptionNoIgnores() Option {
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionNoIgnores())
	}
}

func OptionExcludeRules(ruleIDs []string) Option {
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionExcludeRules(ruleIDs))
	}
}

func OptionIncludeRules(ruleIDs []string) Option {
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionIncludeRules(ruleIDs))
	}
}

func OptionStopOnRuleErrors(stop bool) Option {
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionStopOnErrors(stop))
	}
}

func OptionWithWorkspaceName(name string) Option {
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionWithWorkspaceName(name))
		s.parserOpt = append(s.parserOpt, parser.OptionWithWorkspaceName(name))
	}
}

func OptionWithSingleThread(single bool) Option {
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionWithSingleThread(single))
	}
}

func OptionScanAllDirectories(all bool) Option {
	return func(s *Scanner) {
		s.forceAllDirs = all
	}
}

func OptionWithTFVarsPaths(paths []string) Option {
	return func(s *Scanner) {
		s.parserOpt = append(s.parserOpt, parser.OptionWithTFVarsPaths(paths))
	}
}

func OptionStopOnHCLError(stop bool) Option {
	return func(s *Scanner) {
		s.parserOpt = append(s.parserOpt, parser.OptionStopOnHCLError(stop))
	}
}

func OptionSkipDownloaded(skip bool) Option {
	return func(s *Scanner) {
		if !skip {
			return
		}
		s.executorOpt = append(s.executorOpt, executor.OptionWithResultsFilter(func(results scan.Results) scan.Results {
			for i, result := range results {
				if result.Range() == nil {
					continue
				}
				prefix := result.Range().GetSourcePrefix()
				switch {
				case prefix == "":
				case strings.HasPrefix(prefix, "."):
				default:
					results[i].OverrideStatus(scan.StatusIgnored)
				}
			}
			return results
		}))
	}
}

func OptionWithResultsFilter(f func(scan.Results) scan.Results) Option {
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionWithResultsFilter(f))
	}
}

func OptionWithMinimumSeverity(minimum severity.Severity) Option {
	min := severityAsOrdinal(minimum)
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionWithResultsFilter(func(results scan.Results) scan.Results {
			for i, result := range results {
				if severityAsOrdinal(result.Severity()) < min {
					results[i].OverrideStatus(scan.StatusIgnored)
				}
			}
			return results
		}))
	}
}

// OptionWithPolicyDirs - location of rego policy directories - policies are loaded recursively
func OptionWithPolicyDirs(dirs ...string) func(s *Scanner) {
	return func(s *Scanner) {
		s.policyDirs = dirs
	}
}

// OptionWithDataDirs - location of rego data directories
func OptionWithDataDirs(dirs ...string) func(s *Scanner) {
	return func(s *Scanner) {
		s.dataDirs = dirs
	}
}

// OptionWithPolicyNamespaces - namespaces which indicate rego policies containing enforced rules
func OptionWithPolicyNamespaces(namespaces ...string) func(s *Scanner) {
	return func(s *Scanner) {
		s.policyNamespaces = namespaces
	}
}

func severityAsOrdinal(sev severity.Severity) int {
	switch sev {
	case severity.Critical:
		return 4
	case severity.High:
		return 3
	case severity.Medium:
		return 2
	case severity.Low:
		return 1
	default:
		return 0
	}
}

func OptionWithStateFunc(f ...func(*state.State)) Option {
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionWithStateFunc(f...))
	}
}

func OptionWithDownloads(allowed bool) Option {
	return func(s *Scanner) {
		s.parserOpt = append(s.parserOpt, parser.OptionWithDownloads(allowed))
	}
}

func OptionWithRegoOnly(regoOnly bool) Option {
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionWithRegoOnly(regoOnly))
	}
}

func OptionWithPerResultTracing() Option {
	return func(s *Scanner) {
		s.traceWriter = io.Discard
	}
}
