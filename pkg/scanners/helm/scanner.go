package helm

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/aquasecurity/defsec/internal/debug"
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/helm/parser"
	kparser "github.com/aquasecurity/defsec/pkg/scanners/kubernetes/parser"
	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/rego"
)

type Scanner struct {
	chartName  string
	policyDirs []string
	dataDirs   []string
	paths      []string
	debug      debug.Logger

	policyReaders []io.Reader
	regoScanner   *rego.Scanner
	parser        *parser.Parser
	skipRequired  bool
}

// New creates a new Scanner
func New(chartName string, options ...options.ScannerOption) *Scanner {
	s := &Scanner{
		chartName: chartName,
	}
	for _, option := range options {
		option(s)
	}
	return s
}

func (s *Scanner) Name() string {
	return "Helm"
}

func (s *Scanner) SetPolicyReaders(readers []io.Reader) {
	s.policyReaders = readers
}

func (s *Scanner) SetSkipRequiredCheck(skip bool) {
	s.skipRequired = skip
}

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.debug = debug.New(writer, "scan:helm")
}

func (s *Scanner) SetTraceWriter(_ io.Writer) {
	// handled by rego later - nothing to do for now...
}

func (s *Scanner) SetPerResultTracingEnabled(_ bool) {
	// handled by rego later - nothing to do for now...
}

func (s *Scanner) SetPolicyDirs(dirs ...string) {
	s.policyDirs = dirs
}

func (s *Scanner) SetDataDirs(_ ...string) {
	// handled by rego later - nothing to do for now...
}

func (s *Scanner) SetPolicyNamespaces(_ ...string) {
	// handled by rego later - nothing to do for now...
}

func (s *Scanner) SetPolicyFilesystem(_ fs.FS) {
	// handled by rego when option is passed on
}

func (s *Scanner) ScanFS(ctx context.Context, fs fs.FS, path string) (scan.Results, error) {

	helmParser := parser.New(s.chartName)

	if err := helmParser.ParseFS(ctx, fs, path); err != nil {
		return nil, err
	}

	chartFiles, err := helmParser.RenderedChartFiles()
	if err != nil {
		return nil, err
	}

	var results []scan.Result
	regoScanner := rego.NewScanner()
	if err := regoScanner.LoadPolicies(true, nil, nil, nil); err != nil {
		return nil, fmt.Errorf("policies load: %w", err)
	}
	for _, file := range chartFiles {
		s.debug.Log("Processing rendered chart file: %s", file.TemplateFilePath)

		manifest, err := kparser.New().Parse(strings.NewReader(file.ManifestContent))
		if err != nil {
			return nil, fmt.Errorf("unmarshal yaml: %w", err)
		}
		fileResults, err := regoScanner.ScanInput(context.Background(), rego.Input{
			Path:     file.TemplateFilePath,
			Contents: manifest,
			Type:     types.SourceKubernetes,
		})
		if err != nil {
			return nil, fmt.Errorf("scanning error: %w", err)
		}
		results = append(results, fileResults...)
	}

	return results, nil

}
