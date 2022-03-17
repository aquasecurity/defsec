package terraform

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/scanners/terraform/executor"
	"github.com/aquasecurity/defsec/severity"

	"github.com/aquasecurity/defsec/parsers/terraform/parser"
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

func OptionWithDebugWriter(w io.Writer) Option {
	return func(s *Scanner) {
		s.debugWriter = w
		s.executorOpt = append(s.executorOpt, executor.OptionWithDebugWriter(w))
		s.parserOpt = append(s.parserOpt, parser.OptionWithDebugWriter(w))
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
		s.executorOpt = append(s.executorOpt, executor.OptionWithResultsFilter(func(results rules.Results) rules.Results {
			for i, result := range results {
				if result.Range() == nil {
					continue
				}
				search := fmt.Sprintf("%c.terraform%c", filepath.Separator, filepath.Separator)
				if strings.Contains(result.Range().GetFilename(), search) {
					results[i].OverrideStatus(rules.StatusIgnored)
				}
			}
			return results
		}))
	}
}

func OptionWithExcludePaths(paths []string) Option {
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionWithResultsFilter(func(results rules.Results) rules.Results {
			for i, result := range results {
				if result.Range() == nil {
					continue
				}
				good := true
				for _, exclude := range paths {
					abs, err := filepath.Abs(exclude)
					if err != nil {
						continue
					}
					if str, err := filepath.Rel(abs, result.Range().GetFilename()); err == nil && !strings.HasPrefix(str, "..") {
						good = false
						break
					}
				}
				if !good {
					results[i].OverrideStatus(rules.StatusIgnored)
				}
			}
			return results
		}))
	}
}

func OptionWithMinimumSeverity(minimum severity.Severity) Option {
	min := severityAsOrdinal(minimum)
	return func(s *Scanner) {
		s.executorOpt = append(s.executorOpt, executor.OptionWithResultsFilter(func(results rules.Results) rules.Results {
			for i, result := range results {
				if severityAsOrdinal(result.Severity()) < min {
					results[i].OverrideStatus(rules.StatusIgnored)
				}
			}
			return results
		}))
	}
}

// OptionWithPolicyDirs - location of rego policy directories - policies are loaded recursively
func OptionWithPolicyDirs(dirs []string) func(s *Scanner) {
	return func(s *Scanner) {
		s.policyDirs = dirs
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
