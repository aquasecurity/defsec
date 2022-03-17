package executor

import (
	"io"

	"github.com/aquasecurity/defsec/rego"

	"github.com/aquasecurity/defsec/rules"
)

type Option func(s *Executor)

func OptionWithAlternativeIDProvider(f func(string) []string) Option {
	return func(s *Executor) {
		s.alternativeIDProviderFunc = f
	}
}

func OptionWithResultsFilter(f func(rules.Results) rules.Results) Option {
	return func(s *Executor) {
		s.resultsFilters = append(s.resultsFilters, f)
	}
}

func OptionWithSeverityOverrides(overrides map[string]string) Option {
	return func(s *Executor) {
		s.severityOverrides = overrides
	}
}

func OptionWithDebugWriter(w io.Writer) Option {
	return func(s *Executor) {
		s.debugWriter = w
	}
}

func OptionNoIgnores() Option {
	return func(s *Executor) {
		s.enableIgnores = false
	}
}

func OptionExcludeRules(ruleIDs []string) Option {
	return func(s *Executor) {
		s.excludedRuleIDs = ruleIDs
	}
}

func OptionIncludeRules(ruleIDs []string) Option {
	return func(s *Executor) {
		s.includedRuleIDs = ruleIDs
	}
}

func OptionStopOnErrors(stop bool) Option {
	return func(s *Executor) {
		s.ignoreCheckErrors = !stop
	}
}

func OptionWithWorkspaceName(workspaceName string) Option {
	return func(s *Executor) {
		s.workspaceName = workspaceName
	}
}

func OptionWithSingleThread(single bool) Option {
	return func(s *Executor) {
		s.useSingleThread = single
	}
}

func OptionWithRegoScanner(s *rego.Scanner) Option {
	return func(e *Executor) {
		e.regoScanner = s
	}
}
