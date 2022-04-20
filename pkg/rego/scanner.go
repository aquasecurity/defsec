package rego

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/open-policy-agent/opa/ast"

	"github.com/open-policy-agent/opa/storage"

	"github.com/open-policy-agent/opa/rego"
)

type Scanner struct {
	ruleNamespaces map[string]struct{}
	policies       map[string]*ast.Module
	store          storage.Store
	dataDirs       []string
	runtimeValues  *ast.Term
	compiler       *ast.Compiler
	debugWriter    io.Writer
	traceWriter    io.Writer
	retriever      *MetadataRetriever
}

type DynamicMetadata struct {
	Warning   bool
	Filepath  string
	Message   string
	StartLine int
	EndLine   int
}

func NewScanner(options ...Option) *Scanner {
	s := &Scanner{
		ruleNamespaces: map[string]struct{}{
			"appshield": {},
			"defsec":    {},
		},
		runtimeValues: addRuntimeValues(),
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

func getModuleNamespace(module *ast.Module) string {
	return strings.TrimPrefix(module.Package.Path.String(), "data.")
}

func (s *Scanner) debug(format string, args ...interface{}) {
	if s.debugWriter == nil {
		return
	}
	prefix := "[debug:scan:rego] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (s *Scanner) runQuery(ctx context.Context, query string, input interface{}, disableTracing bool) (rego.ResultSet, []string, error) {

	trace := s.traceWriter != nil && !disableTracing

	options := []func(*rego.Rego){
		rego.Query(query),
		rego.Compiler(s.compiler),
		rego.Store(s.store),
		rego.Runtime(s.runtimeValues),
		rego.Trace(trace),
	}

	if input != nil {
		options = append(options, rego.Input(input))
	}

	instance := rego.New(options...)
	set, err := instance.Eval(ctx)
	if err != nil {
		return nil, nil, err
	}

	// we also build a slice of trace lines for per-result tracing - primarily for fanal/trivy
	var traces []string

	if trace {
		rego.PrintTrace(s.traceWriter, instance)
		traceBuffer := bytes.NewBuffer([]byte{})
		rego.PrintTrace(traceBuffer, instance)
		traces = strings.Split(traceBuffer.String(), "\n")
	}
	return set, traces, nil
}

type Input struct {
	Path     string       `json:"path"`
	Contents interface{}  `json:"contents"`
	Type     types.Source `json:"type"`
}

func (s *Scanner) ScanInput(ctx context.Context, inputs ...Input) (scan.Results, error) {

	s.debug("Scanning %d inputs...", len(inputs))

	var results scan.Results
	var filteredInputs []Input

	for _, module := range s.policies {

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		namespace := getModuleNamespace(module)
		topLevel := strings.Split(namespace, ".")[0]
		if _, ok := s.ruleNamespaces[topLevel]; !ok {
			continue
		}

		staticMeta, err := s.retriever.RetrieveMetadata(ctx, module)
		if err != nil {
			return nil, err
		}

		if len(staticMeta.InputOptions.Selectors) > 0 {
			filteredInputs = nil
			for _, in := range inputs {
				var match bool
				for _, selector := range staticMeta.InputOptions.Selectors {
					if selector.Type == string(in.Type) {
						match = true
						break
					}
				}
				if match {
					filteredInputs = append(filteredInputs, in)
				}
			}
		} else {
			filteredInputs = make([]Input, len(inputs))
			copy(filteredInputs, inputs)
		}

		if len(filteredInputs) == 0 {
			continue
		}

		// all rules
		for _, rule := range module.Rules {
			ruleName := rule.Head.Name.String()
			if isEnforcedRule(ruleName) {
				ruleResults, err := s.applyRule(ctx, namespace, ruleName, filteredInputs, staticMeta.InputOptions.Combined)
				if err != nil {
					return nil, err
				}
				results = append(results, s.embellishResultsWithRuleMetadata(ruleResults, *staticMeta)...)
			}
		}

	}

	return results, nil
}

func (s *Scanner) applyRule(ctx context.Context, namespace string, rule string, inputs []Input, combined bool) (scan.Results, error) {

	// handle combined evaluations if possible
	if combined {
		return s.applyRuleCombined(ctx, namespace, rule, inputs)
	}

	var results scan.Results
	qualified := fmt.Sprintf("data.%s.%s", namespace, rule)
	for _, input := range inputs {
		if ignored, err := s.isIgnored(ctx, namespace, rule, input); err != nil {
			return nil, err
		} else if ignored {
			var result regoResult
			result.Filepath = input.Path
			result.Managed = true
			results.AddIgnored(result)
			continue
		}
		set, traces, err := s.runQuery(ctx, qualified, input.Contents, false)
		if err != nil {
			return nil, err
		}
		ruleResults := s.convertResults(set, input.Path, namespace, rule, traces)
		if len(ruleResults) == 0 {
			var result regoResult
			result.Filepath = input.Path
			result.Managed = true
			results.AddPassed(result)
			continue
		}
		results = append(results, ruleResults...)
	}

	return results, nil
}

func (s *Scanner) applyRuleCombined(ctx context.Context, namespace string, rule string, inputs []Input) (scan.Results, error) {
	var results scan.Results
	qualified := fmt.Sprintf("data.%s.%s", namespace, rule)
	if ignored, err := s.isIgnored(ctx, namespace, rule, inputs); err != nil {
		return nil, err
	} else if ignored {
		for _, input := range inputs {
			var result regoResult
			result.Filepath = input.Path
			result.Managed = true
			results.AddIgnored(result)
		}
		return results, nil
	}
	set, traces, err := s.runQuery(ctx, qualified, inputs, false)
	if err != nil {
		return nil, err
	}
	return s.convertResults(set, "", namespace, rule, traces), nil
}

// severity is now set with metadata, so deny/warn/violation now behave the same way
func isEnforcedRule(name string) bool {
	switch {
	case name == "deny", strings.HasPrefix(name, "deny_"),
		name == "warn", strings.HasPrefix(name, "warn_"),
		name == "violation", strings.HasPrefix(name, "violation_"):
		return true
	}
	return false
}
